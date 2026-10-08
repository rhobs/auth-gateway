package config

import (
	"fmt"
	"net"
	"path"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	caDirectory            = "/etc/auth-gateway-ca"
	systemCABundle         = "/etc/ssl/certs/ca-certificates.crt"
	tlsTransportSocketName = "envoy.transport_sockets.tls"
)

func validateTrustedCA(name string, ca *TrustedCA, kubernetes bool) error {
	if ca == nil {
		return nil
	}
	if (ca.Filename != "") == (ca.ConfigMap != nil) {
		return fmt.Errorf("%s must select exactly one of filename or config_map", name)
	}
	if ca.ConfigMap != nil {
		if !kubernetes {
			return fmt.Errorf("%s.config_map requires kubernetes settings to provision the CA mount", name)
		}
		if len(validation.IsDNS1123Subdomain(ca.ConfigMap.Name)) != 0 {
			return fmt.Errorf("%s.config_map.name must be a valid ConfigMap name", name)
		}
		if len(validation.IsConfigMapKey(ca.ConfigMap.Key)) != 0 {
			return fmt.Errorf("%s.config_map.key must be a valid ConfigMap key", name)
		}
		return nil
	}
	if kubernetes {
		return fmt.Errorf("%s.filename is supported only without kubernetes settings; use config_map", name)
	}
	if !path.IsAbs(ca.Filename) || path.Clean(ca.Filename) != ca.Filename || ca.Filename == "/" || strings.ContainsAny(ca.Filename, invalidControlCharacters) {
		return fmt.Errorf("%s.filename must be a clean absolute file path", name)
	}
	return nil
}

func verifiedTLS(identity string, ca *TrustedCA, alpn []string) (*core.TransportSocket, error) {
	sanType := tls.SubjectAltNameMatcher_DNS
	sni := identity
	if ip := net.ParseIP(identity); ip != nil {
		sanType = tls.SubjectAltNameMatcher_IP_ADDRESS
		sni = ""
		identity = ip.String()
	}
	caFilename := systemCABundle
	if ca != nil {
		caFilename = ca.filename()
	}
	packed, err := packEnvoy(&tls.UpstreamTlsContext{
		Sni: sni,
		CommonTlsContext: &tls.CommonTlsContext{
			TlsParams: &tls.TlsParameters{
				TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
				TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
			},
			AlpnProtocols: alpn,
			ValidationContextType: &tls.CommonTlsContext_ValidationContext{ValidationContext: &tls.CertificateValidationContext{
				TrustedCa: fileDataSource(caFilename),
				MatchTypedSubjectAltNames: []*tls.SubjectAltNameMatcher{{
					SanType: sanType,
					Matcher: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: identity}},
				}},
			}},
		},
	})
	if err != nil {
		return nil, err
	}
	return &core.TransportSocket{Name: tlsTransportSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: packed}}, nil
}
