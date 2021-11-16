package common

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/test/tpmsimulator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	fooKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAMB4gbT09H2RKXaxbu6IV9C3WY+pvkGAbrlQRIHLHwV3Xt1HchjX
c08v1VEoTBN2YTjhZJlDb/VUsNMJsmBFBBted5geRcbrDtXFlUJ8tQoQx1dWM4Aa
xcdULJ83A9ICKwIDAQABAmBR1asInrIphYQEtHJ/NzdnRd3tqHV9cjch0dAfA5dA
Ar4yBYOsrkaX37WqWSDnkYgN4FWYBWn7WxeotCtA5UQ3SM5hLld67rUqAm2dLrs1
z8va6SwLzrPTu2+rmRgovFECMQDpbfPBRex7FY/xWu1pYv6X9XZ26SrC2Wc6RIpO
38AhKGjTFEMAPJQlud4e2+4I3KkCMQDTFLUvBSXokw2NvcNiM9Kqo5zCnCIkgc+C
hM3EzSh2jh4gZvRzPOhXYvNKgLx8+LMCMQDL4meXlpV45Fp3eu4GsJqi65jvP7VD
v1P0hs0vGyvbSkpUo0vqNv9G/FNQLNR6FRECMFXEMz5wxA91OOuf8HTFg9Lr+fUl
RcY5rJxm48kUZ12Mr3cQ/kCYvftL7HkYR/4rewIxANdritlIPu4VziaEhYZg7dvz
pG3eEhiqPxE++QHpwU78O+F1GznOPBvpZOB3GfyjNQ==
-----END RSA PRIVATE KEY-----`)

	TrustDomain       = "domain.test"
	TokenRelativePath = "/testing/path"

	DevID                 *tpmsimulator.Credential
	DevIDBundlePath       string
	EndorsementBundlePath string
	TPMDevicePath         = "/dev/tpmrm0"
	DevIDCertPath         string
	DevIDPrivPath         string
	DevIDPubPath          string
	TPMPasswords          = tpmutil.TPMPasswords{
		EndorsementHierarchy: "endorsement-hierarchy-pass",
		OwnerHierarchy:       "owner-hierarchy-pass",
		DevIDKey:             "devid-pass",
	}
)

// PSATData helps move PSAT data around
type PSATData struct {
	Cluster            string
	Namespace          string
	ServiceAccountName string
	PodName            string
	PodUID             string
	NodeIP             string
	NodeName           string
	NodeUID            string
}

// CreatePSAT creates a PSAT using the given namespace and podName (just for testing)
func CreatePSAT(namespace, podName string) (string, error) {
	// Create a jwt builder
	s, err := createSigner()
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(s)

	// Set useful claims for testing
	claims := sat_common.PSATClaims{}
	claims.K8s.Namespace = namespace
	claims.K8s.Pod.Name = podName
	builder = builder.Claims(claims)

	// Serialize and return token
	token, err := builder.CompactSerialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

// SetupTPMSimulator performs a simple setup for the simulator
func SetupTPMSimulator(t *testing.T) *tpmsimulator.TPMSimulator {
	// Creates a new global TPM simulator
	sim, err := tpmsimulator.New(TPMPasswords.EndorsementHierarchy, TPMPasswords.OwnerHierarchy)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, sim.Close(), "unexpected error encountered closing simulator")
	})

	// Replace real openTPM with open simulator
	tpmutil.OpenTPM = sim.OpenTPM

	// Create a temporal directory to store configuration files
	dir := t.TempDir()

	// Create DevID with intermediate cert
	provisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err)

	DevID, err = sim.GenerateDevID(provisioningCA, tpmsimulator.RSA, TPMPasswords.DevIDKey)
	require.NoError(t, err)

	// Write files into temporal directory
	WriteDevIDFiles(t, dir)

	// Write provisioning root certificates into temp directory
	DevIDBundlePath = path.Join(dir, "devid-provisioning-ca.pem")
	require.NoError(t, os.WriteFile(
		DevIDBundlePath,
		pemutil.EncodeCertificate(provisioningCA.RootCert),
		0600),
	)

	// Write endorsement root certificate into temp directory
	EndorsementBundlePath = path.Join(dir, "endorsement-ca.pem")
	require.NoError(t, os.WriteFile(
		EndorsementBundlePath,
		pemutil.EncodeCertificate(sim.GetEKRoot()),
		0600),
	)

	return sim
}

// WriteDevIDFiles writes the DevID certificate, public and private keys into files
func WriteDevIDFiles(t *testing.T, dir string) {
	require.NotNil(t, DevID, "DevID must be set")

	DevIDCertPath = path.Join(dir, "devid-certificate.pem")
	DevIDPrivPath = path.Join(dir, "devid-priv-path")
	DevIDPubPath = path.Join(dir, "devid-pub-path")

	require.NoError(t, os.WriteFile(
		DevIDCertPath,
		DevID.ChainPem(),
		0600),
		"failed to write DevIDCertPath into file")
	require.NoError(t, os.WriteFile(DevIDPrivPath,
		DevID.PrivateBlob,
		0600),
		"failed to write DevIDPrivPath into file")
	require.NoError(t, os.WriteFile(DevIDPubPath,
		DevID.PublicBlob,
		0600),
		"failed to write DevIDPubPath into file")
}

// WriteToken writes the PSAT to a file at given path
func WriteToken(t *testing.T, dir, path, data string) string {
	valuePath := filepath.Join(dir, path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(valuePath, []byte(data), 0600)
	require.NoError(t, err)
	return valuePath
}

// DefaultPSATData returns properly formatted, generic PSAT data
func DefaultPSATData() *PSATData {
	return &PSATData{
		Cluster:            "FOO",
		Namespace:          "NS1",
		ServiceAccountName: "SA1",
		PodName:            "PODNAME-1",
		PodUID:             "PODUID-1",
		NodeIP:             "172.16.10.1",
		NodeName:           "NODENAME-1",
		NodeUID:            "NODEUID-1",
	}
}

func createSigner() (jose.Signer, error) {
	sampleKey, err := pemutil.ParseRSAPrivateKey(fooKeyPEM)
	if err != nil {
		return nil, err
	}

	sampleSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       sampleKey,
	}, nil)

	if err != nil {
		return nil, err
	}

	return sampleSigner, nil
}
