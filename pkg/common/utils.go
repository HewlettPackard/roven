package common

import (
	"net/url"
	"strings"

	common_psat "github.com/spiffe/spire/pkg/common/plugin/k8s"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
)

const (
	PluginName = "k8s_psat_tpm_devid"
)

type AttestationRequest struct {
	DevIDAttestationRequest common_devid.AttestationRequest
	PSATAttestationData     common_psat.PSATAttestationData
}

func AgentID(trustDomain string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   strings.Join([]string{"spire", "agent", "devid", "psat"}, "/"),
	}
	return u.String()
}
