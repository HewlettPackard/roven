package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/hewlettpackard/roven/pkg/common"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	//nolint
	defaultTokenPath = "/var/run/secrets/tokens/spire-agent"
	baseTPMDir       = "/dev"
)

// Functions defined here are overridden in test files to facilitate unit testing
var (
	AutoDetectTPMPath func(string) (string, error)                           = tpmutil.AutoDetectTPMPath
	NewSession        func(*tpmutil.SessionConfig) (*tpmutil.Session, error) = tpmutil.NewSession
)

// AttestorPlugin implements the nodeattestor Plugin interface
type AttestorPlugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu     sync.RWMutex
	config *attestorConfig
	logger hclog.Logger
}

type AttestorConfig struct {
	// Cluster is the cluster name
	Cluster string `hcl:"cluster"`
	// TokenPath is the path to the projected service account token
	TokenPath string `hcl:"token_path"`

	// DevIDPrivPath is the path to the devId's private blob
	DevIDPrivPath string `hcl:"devid_priv_path"`
	// DevIDPubPath is the path to the devId's public blob
	DevIDPubPath string `hcl:"devid_pub_path"`
	// DevIDCertPath is the path to the devId's bundle
	DevIDCertPath string `hcl:"devid_cert_path"`

	// DevIDKeyPassword is the private key password
	DevIDKeyPassword string `hcl:"devid_password"`
	// OwnerHierarchyPassword is the admin hierarchy key password
	OwnerHierarchyPassword string `hcl:"owner_hierarchy_password"`
	// EndorsementHierarchyPassword is the endorsement hierarchy key password
	EndorsementHierarchyPassword string `hcl:"endorsement_hierarchy_password"`

	// DevicePath is the TPM device (socket or device files)
	DevicePath string `hcl:"tpm_device_path"`
}

type attestorConfig struct {
	cluster    string
	tokenPath  string
	devicePath string
	devIDCert  [][]byte
	devIDPub   []byte
	devIDPriv  []byte
	passwords  tpmutil.TPMPasswords
}

func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

func (p *AttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	hclConfig := &AttestorConfig{}
	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if err := validatePluginConfig(hclConfig); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: %v", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = &attestorConfig{
		cluster:   hclConfig.Cluster,
		tokenPath: hclConfig.TokenPath,
	}

	if p.config.tokenPath == "" {
		p.config.tokenPath = defaultTokenPath
	}
	p.config.devicePath = hclConfig.DevicePath
	if p.config.devicePath == "" {
		tpmPath, err := tpmutil.AutoDetectTPMPath(baseTPMDir)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "tpm autodetection failed: %v", err)
		}
		p.config.devicePath = tpmPath
	}

	if err := p.loadDevIDFiles(hclConfig); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to load DevID files: %v", err)
	}

	p.config.passwords.DevIDKey = hclConfig.DevIDKeyPassword
	p.config.passwords.OwnerHierarchy = hclConfig.OwnerHierarchyPassword
	p.config.passwords.EndorsementHierarchy = hclConfig.EndorsementHierarchyPassword

	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	// First, performs PSAT attestation steps
	token, err := loadTokenFromFile(p.config.tokenPath)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to load token from %s: %v", p.config.tokenPath, err)
	}

	// Storing PSAT attestation data to be sent in conjunction with TPM payload
	psatAttestationData := k8s.PSATAttestationData{
		Cluster: p.config.cluster,
		Token:   token,
	}

	// Now, start DevID attestation
	// Open TPM connection and load DevID keys
	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevicePath: config.devicePath,
		DevIDPriv:  config.devIDPriv,
		DevIDPub:   config.devIDPub,
		Passwords:  config.passwords,
		Log:        p.logger,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to start a new TPM session: %v", err)
	}
	defer tpm.Close()

	// Get endorsement certificate from TPM NV index
	ekCert, err := tpm.GetEKCert()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to get endorsement certificate: %v", err)
	}

	// Get regenerated endorsement public key
	ekPub, err := tpm.GetEKPublic()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to get endorsement public key: %v", err)
	}

	// Certify DevID is in the same TPM as AK
	id, sig, err := tpm.CertifyDevIDKey()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to certify DevID key: %v", err)
	}

	// Marshal PSAT and DevID attestation data
	payload, err := json.Marshal(common.AttestationRequest{
		DevIDAttestationRequest: common_devid.AttestationRequest{
			DevIDCert: config.devIDCert,
			DevIDPub:  config.devIDPub,

			EKCert: ekCert,
			EKPub:  ekPub,

			AKPub: tpm.GetAKPublic(),

			CertifiedDevID:         id,
			CertificationSignature: sig,
		},
		PSATAttestationData: psatAttestationData,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	// Send attestation request
	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
		},
	})
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send attestation data: %s", st.Message())
	}

	// Receive challenges (PSAT attestation OK)
	marshalledChallenges, err := stream.Recv()
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to receive challenges: %s", st.Message())
	}

	challenges := &common_devid.ChallengeRequest{}
	if err = json.Unmarshal(marshalledChallenges.Challenge, challenges); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall challenges: %v", err)
	}

	// Solve DevID challenge (verify the possession of the DevID private key)
	devIDChallengeResp, err := tpm.SolveDevIDChallenge(challenges.DevID)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to solve proof of possession challenge: %v", err)
	}

	// Solve Credential Activation challenge
	var credActChallengeResp []byte
	if challenges.CredActivation == nil {
		return status.Error(codes.Internal, "received empty credential activation challenge from server")
	}

	credActChallengeResp, err = tpm.SolveCredActivationChallenge(
		challenges.CredActivation.Credential,
		challenges.CredActivation.Secret)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to solve proof of residency challenge: %v", err)
	}

	// Marshal challenges responses
	marshalledChallengeResp, err := json.Marshal(common_devid.ChallengeResponse{
		DevID:          devIDChallengeResp,
		CredActivation: credActChallengeResp,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge response: %v", err)
	}

	// Send challenge response back to the server
	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: marshalledChallengeResp,
		},
	})
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send challenge response: %s", st.Message())
	}

	return nil
}

func (p *AttestorPlugin) loadDevIDFiles(c *AttestorConfig) error {
	certs, err := util.LoadCertificates(c.DevIDCertPath)
	if err != nil {
		return fmt.Errorf("cannot load certificate(s): %w", err)
	}

	for _, cert := range certs {
		p.config.devIDCert = append(p.config.devIDCert, cert.Raw)
	}

	p.config.devIDPriv, err = ioutil.ReadFile(c.DevIDPrivPath)
	if err != nil {
		return fmt.Errorf("cannot load private key: %w", err)
	}

	p.config.devIDPub, err = ioutil.ReadFile(c.DevIDPubPath)
	if err != nil {
		return fmt.Errorf("cannot load public key: %w", err)
	}

	return nil
}

func (p *AttestorPlugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func loadTokenFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errs.Wrap(err)
	}
	if len(data) == 0 {
		return "", errs.New("%q is empty", path)
	}
	return string(data), nil
}

func validatePluginConfig(c *AttestorConfig) error {
	switch {
	case c.DevIDCertPath == "":
		return errors.New("devid_cert_path is required")

	case c.DevIDPrivPath == "":
		return errors.New("devid_priv_path is required")

	case c.DevIDPubPath == "":
		return errors.New("devid_pub_path is required")

	case c.Cluster == "":
		return errors.New("cluster is required")
	}

	return nil
}
