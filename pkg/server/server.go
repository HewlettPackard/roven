package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/hewlettpackard/roven/pkg/common"

	"github.com/google/go-tpm/tpm2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/tpmdevid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// Using a 32 bytes nonce to provide enough cryptographical randomness and to be
	// consistent with other nonces sizes around the project.
	devIDChallengeNonceSize = 32
)

var (
	defaultAudience = []string{"spire-server"}
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
	// Clusters map cluster names to cluster config
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
	// DevIDBundlePath is the DevID trust bundle path
	DevIDBundlePath string `hcl:"devid_ca_path"`
	// EndorsementBundlePath is the Endorsement root CA bundle path
	EndorsementBundlePath string `hcl:"endorsement_ca_path"`
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// Array of allowed service accounts names
	// Attestation is denied if coming from a service account that is not in the list
	ServiceAccountAllowList []string `hcl:"service_account_allow_list"`

	// Audience for PSAT token validation
	// If audience is not configured, defaultAudience will be used
	// If audience value is set to an empty slice, k8s apiserver audience will be used
	Audience *[]string `hcl:"audience"`

	// Kubernetes configuration file path
	// Used to create a k8s client to query the API server. If string is empty, in-cluster configuration is used
	KubeConfigFile string `hcl:"kube_config_file"`

	// Node labels that are allowed to use as selectors
	AllowedNodeLabelKeys []string `hcl:"allowed_node_label_keys"`

	// Pod labels that are allowed to use as selectors
	AllowedPodLabelKeys []string `hcl:"allowed_pod_label_keys"`
}

type clusterConfig struct {
	serviceAccounts      map[string]bool
	audience             []string
	client               apiserver.Client
	allowedNodeLabelKeys map[string]bool
	allowedPodLabelKeys  map[string]bool
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig

	devIDRoots *x509.CertPool
	ekRoots    *x509.CertPool
}

func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

func (p *AttestorPlugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *AttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	var err error
	hclConfig := &AttestorConfig{}
	if err = hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration file: %v", err)
	}

	if err = validateCoreConfig(req, hclConfig); err != nil {
		return nil, err
	}

	config := &attestorConfig{
		trustDomain: req.CoreConfiguration.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}

	if err = validateClusterConfig(hclConfig.Clusters, config); err != nil {
		return nil, err
	}

	if err = validateDevIDConfig(hclConfig); err != nil {
		return nil, err
	}

	// Load DevID bundle
	if config.devIDRoots, err = util.LoadCertPool(hclConfig.DevIDBundlePath); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to load endorsement trust bundle: %v", err)
	}
	// Load endorsement bundle if configured
	if config.ekRoots, err = util.LoadCertPool(hclConfig.EndorsementBundlePath); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to load endorsement trust bundle: %v", err)
	}

	p.setConfig(config)

	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	attestationData := new(common.AttestationRequest)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data payload: %v", err)
	}
	// Perform PSAT validation
	psatAttestationData := attestationData.PSATAttestationData

	if psatAttestationData.Cluster == "" {
		return status.Error(codes.InvalidArgument, "missing cluster in attestation data")
	}

	if psatAttestationData.Token == "" {
		return status.Error(codes.InvalidArgument, "missing token in attestation data")
	}

	cluster := config.clusters[psatAttestationData.Cluster]
	if cluster == nil {
		return status.Errorf(codes.InvalidArgument, "not configured for cluster %q", psatAttestationData.Cluster)
	}

	tokenStatus, err := cluster.client.ValidateToken(stream.Context(), psatAttestationData.Token, cluster.audience)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to validate token with TokenReview API: %v", err)
	}

	if !tokenStatus.Authenticated {
		return status.Error(codes.PermissionDenied, "token not authenticated according to TokenReview API")
	}

	namespace, serviceAccountName, err := k8s.GetNamesFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to parse username from token review status: %v", err)
	}
	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)

	if !cluster.serviceAccounts[fullServiceAccountName] {
		return status.Errorf(codes.PermissionDenied, "%q is not an allowed service account", fullServiceAccountName)
	}

	podName, err := k8s.GetPodNameFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod name from token review status: %v", err)
	}

	podUID, err := k8s.GetPodUIDFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod UID from token review status: %v", err)
	}

	pod, err := cluster.client.GetPod(stream.Context(), namespace, podName)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod from k8s API server: %v", err)
	}

	node, err := cluster.client.GetNode(stream.Context(), pod.Spec.NodeName)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get node from k8s API server: %v", err)
	}

	nodeUID := string(node.UID)
	if nodeUID == "" {
		return status.Errorf(codes.Internal, "node UID is empty")
	}

	// Perform TPM validation
	devidAttestationData := &attestationData.DevIDAttestationRequest

	// Decode attestation data
	if len(devidAttestationData.DevIDCert) == 0 {
		return status.Error(codes.InvalidArgument, "no DevID certificate to attest")
	}

	devIDCert, err := x509.ParseCertificate(devidAttestationData.DevIDCert[0])
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to parse DevID certificate: %v", err)
	}

	devIDIntermediates := x509.NewCertPool()
	for i, intermediatesBytes := range devidAttestationData.DevIDCert[1:] {
		intermediate, err := x509.ParseCertificate(intermediatesBytes)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "unable to parse DevID intermediate certificate %d: %v", i, err)
		}
		devIDIntermediates.AddCert(intermediate)
	}

	// Verify DevID certificate chain of trust
	chains, err := verifyDevIDSignature(devIDCert, devIDIntermediates, config.devIDRoots)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to verify DevID signature: %v", err)
	}

	// Issue a DevID challenge (to prove the possession of the DevID private key).
	devIDChallenge, err := newNonce(devIDChallengeNonceSize)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to generate challenge: %v", err)
	}

	// Verify DevID residency
	var nonce []byte
	var credActivationChallenge *common_devid.CredActivation
	credActivationChallenge, nonce, err = verifyDevIDResidency(devidAttestationData, config.ekRoots)
	if err != nil {
		return err
	}

	// Marshal challenges
	challenge, err := json.Marshal(common_devid.ChallengeRequest{
		DevID:          devIDChallenge,
		CredActivation: credActivationChallenge,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenges data: %v", err)
	}

	// Send challenges to the agent
	err = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challenge,
		},
	})
	if err != nil {
		return status.Errorf(status.Code(err), "unable to send challenges: %v", err)
	}

	// Receive challenges response
	responseReq, err := stream.Recv()
	if err != nil {
		return status.Errorf(status.Code(err), "unable to receive challenges response: %v", err)
	}

	// Unmarshal challenges response
	challengeResponse := &common_devid.ChallengeResponse{}
	if err = json.Unmarshal(responseReq.GetChallengeResponse(), challengeResponse); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall challenges response: %v", err)
	}

	// Verify DevID challenge
	err = tpmdevid.VerifyDevIDChallenge(devIDCert, devIDChallenge, challengeResponse.DevID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "devID challenge verification failed: %v", err)
	}

	// Verify credential activation challenge
	err = tpmdevid.VerifyCredActivationChallenge(nonce, challengeResponse.CredActivation)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "credential activation failed: %v", err)
	}

	td, err := spiffeid.TrustDomainFromString(config.trustDomain)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to generate trust domain: %v", err)
	}
	// Create SPIFFE ID and selectors
	id, err := idutil.AgentID(td, agentPath(psatAttestationData.Cluster, nodeUID))
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to generate spiffeID: %v", err)
	}
	k8sSelectors := []string{
		k8s.MakeSelectorValue("cluster", psatAttestationData.Cluster),
		k8s.MakeSelectorValue("agent_ns", namespace),
		k8s.MakeSelectorValue("agent_sa", serviceAccountName),
		k8s.MakeSelectorValue("agent_pod_name", podName),
		k8s.MakeSelectorValue("agent_pod_uid", podUID),
		k8s.MakeSelectorValue("agent_node_ip", pod.Status.HostIP),
		k8s.MakeSelectorValue("agent_node_name", pod.Spec.NodeName),
		k8s.MakeSelectorValue("agent_node_uid", nodeUID),
	}

	for key, value := range node.Labels {
		if cluster.allowedNodeLabelKeys[key] {
			k8sSelectors = append(k8sSelectors, k8s.MakeSelectorValue("agent_node_label", key, value))
		}
	}

	for key, value := range pod.Labels {
		if cluster.allowedPodLabelKeys[key] {
			k8sSelectors = append(k8sSelectors, k8s.MakeSelectorValue("agent_pod_label", key, value))
		}
	}

	selectors := appendDevIDSelectorValues(k8sSelectors, devIDCert, chains)

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       id.String(),
				SelectorValues: selectors,
			},
		},
	})
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *AttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func validateCoreConfig(req *configv1.ConfigureRequest, hclConfig *AttestorConfig) error {
	if req.CoreConfiguration == nil {
		return status.Error(codes.InvalidArgument, "core configuration is required")
	}
	if req.CoreConfiguration.TrustDomain == "" {
		return status.Error(codes.InvalidArgument, "trust_domain is required")
	}
	if len(hclConfig.Clusters) == 0 {
		return status.Error(codes.InvalidArgument, "configuration must have at least one cluster")
	}

	return nil
}

func validateClusterConfig(clusters map[string]*ClusterConfig, config *attestorConfig) error {
	for name, cluster := range clusters {
		if len(cluster.ServiceAccountAllowList) == 0 {
			return status.Errorf(codes.InvalidArgument, "cluster %q configuration must have at least one service account allowed", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountAllowList {
			serviceAccounts[serviceAccount] = true
		}

		var audience []string
		if cluster.Audience == nil {
			audience = defaultAudience
		} else {
			audience = *cluster.Audience
		}

		allowedNodeLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedNodeLabelKeys {
			allowedNodeLabelKeys[label] = true
		}

		allowedPodLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedPodLabelKeys {
			allowedPodLabelKeys[label] = true
		}

		config.clusters[name] = &clusterConfig{
			serviceAccounts:      serviceAccounts,
			audience:             audience,
			client:               apiserver.New(cluster.KubeConfigFile),
			allowedNodeLabelKeys: allowedNodeLabelKeys,
			allowedPodLabelKeys:  allowedPodLabelKeys,
		}
	}
	return nil
}

func validateDevIDConfig(config *AttestorConfig) error {
	switch {
	case config.DevIDBundlePath == "":
		return status.Error(codes.InvalidArgument, "devid_ca_path is required")
	case config.EndorsementBundlePath == "":
		return status.Error(codes.InvalidArgument, "endorsement_ca_path is required")
	}

	return nil
}

func verifyDevIDSignature(cert *x509.Certificate, intermediates *x509.CertPool, roots *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Intermediates: intermediates,
	})
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return chains, nil
}

func newNonce(size int) ([]byte, error) {
	nonce, err := common_devid.GetRandomBytes(size)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

// verifyDevIDResidency verifies that the DevID resides on the same TPM as EK.
// This is done in two steps:
// (1) Verify that the DevID resides in the same TPM than the AK
// (2) Verify that the AK is in the same TPM than the EK.
// The verification is complete once the agent solves the challenge that this
// function generates.
func verifyDevIDResidency(attData *common_devid.AttestationRequest, ekRoots *x509.CertPool) (*common_devid.CredActivation, []byte, error) {
	// Check that request contains all the information required to validate DevID residency
	err := isDevIDResidencyInfoComplete(attData)
	if err != nil {
		return nil, nil, err
	}

	// Decode attestation data
	ekCert, err := x509.ParseCertificate(attData.EKCert)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot parse endorsement certificate: %v", err)
	}

	devIDPub, err := tpm2.DecodePublic(attData.DevIDPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot decode DevID key public blob: %v", err)
	}

	akPub, err := tpm2.DecodePublic(attData.AKPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot decode attestation key public blob: %v", err)
	}

	ekPub, err := tpm2.DecodePublic(attData.EKPub)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, "cannot decode endorsement key public blob")
	}

	// Verify the public part of the EK generated from the template is the same
	// than the one in the EK certificate.
	err = verifyEKsMatch(ekCert, ekPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "public key in EK certificate differs from public key created via EK template: %v", err)
	}

	// Verify EK chain of trust using the provided manufacturer roots.
	err = verifyEKSignature(ekCert, ekRoots)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot verify EK signature: %v", err)
	}

	// Verify DevID resides in the same TPM than AK
	err = tpmdevid.VerifyDevIDCertification(&akPub, &devIDPub, attData.CertifiedDevID, attData.CertificationSignature)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot verify that DevID is in the same TPM than AK: %v", err)
	}

	// Issue a credential activation challenge (to verify AK is in the same TPM than EK)
	challenge, nonce, err := tpmdevid.NewCredActivationChallenge(akPub, ekPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "cannot generate credential activation challenge: %v", err)
	}

	return challenge, nonce, nil
}

func isDevIDResidencyInfoComplete(attReq *common_devid.AttestationRequest) error {
	if len(attReq.AKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing attestation key public blob")
	}

	if len(attReq.DevIDPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing DevID key public blob")
	}

	if len(attReq.EKCert) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement certificate")
	}

	if len(attReq.EKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement key public blob")
	}

	return nil
}

func verifyEKSignature(ekCert *x509.Certificate, roots *x509.CertPool) error {
	// Check UnhandledCriticalExtensions for OIDs that we know what to do about
	// it (e.g. it's safe to ignore)
	subjectAlternativeNameOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	unhandledExtensions := []asn1.ObjectIdentifier{}
	for _, oid := range ekCert.UnhandledCriticalExtensions {
		// Endorsement certificate's SAN is not fully processed by x509 package
		if !oid.Equal(subjectAlternativeNameOID) {
			unhandledExtensions = append(unhandledExtensions, oid)
		}
	}

	ekCert.UnhandledCriticalExtensions = unhandledExtensions

	_, err := ekCert.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	})
	if err != nil {
		return fmt.Errorf("endorsement certificate verification failed: %w", err)
	}

	return nil
}

// verifyEKsMatch checks that the public key generated using the EK template
// matches the public key included in the Endorsement Certificate.
func verifyEKsMatch(ekCert *x509.Certificate, ekPub tpm2.Public) error {
	keyFromCert, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("key from certificate is not an RSA key")
	}

	cryptoKey, err := ekPub.Key()
	if err != nil {
		return fmt.Errorf("cannot get template key: %w", err)
	}

	keyFromTemplate, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("key from template is not an RSA key")
	}

	if keyFromCert.E != keyFromTemplate.E {
		return errors.New("exponent mismatch")
	}

	if keyFromCert.N.Cmp(keyFromTemplate.N) != 0 {
		return errors.New("modulus mismatch")
	}

	return nil
}

// appends all fingerprints to all psat selectors
func appendDevIDSelectorValues(selectors []string, leaf *x509.Certificate, chains [][]*x509.Certificate) []string {
	if leaf.Subject.CommonName != "" {
		selectors = append(selectors, "subject:cn:"+leaf.Subject.CommonName)
	}

	if leaf.Issuer.CommonName != "" {
		selectors = append(selectors, "issuer:cn:"+leaf.Issuer.CommonName)
	}

	// Used to avoid duplicating selectors.
	fingerprints := map[string]*x509.Certificate{}
	for _, chain := range chains {
		// Iterate over all the certs in the chain (skip leaf at the 0 index)
		for _, cert := range chain[1:] {
			fp := tpmdevid.Fingerprint(cert)
			// If the same fingerprint is generated, continue with the next certificate, because
			// a selector should have been already created for it.
			if _, ok := fingerprints[fp]; ok {
				continue
			}
			fingerprints[fp] = cert

			selectors = append(selectors, "ca:fingerprint:"+fp)
		}
	}

	return selectors
}

func agentPath(cluster, uuid string) string {
	return fmt.Sprintf("/%s/%s/%s", common.PluginName, cluster, uuid)
}
