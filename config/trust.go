package config

import (
	"crypto/sha256"
	"encoding/hex"
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
	caDirectory    = "/etc/auth-gateway-ca"
	systemCABundle = "/etc/ssl/certs/ca-certificates.crt"
)

// TrustedCA selects a replacement trust bundle. Omission uses the system bundle.
type TrustedCA struct {
	Filename  string       `yaml:"filename,omitempty"`
	ConfigMap *CAConfigMap `yaml:"config_map,omitempty"`
}

// CAConfigMap references one key of an existing ConfigMap in the gateway namespace.
type CAConfigMap struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

func cloneTrustedCA(value *TrustedCA) *TrustedCA {
	if value == nil {
		return nil
	}
	copy := *value
	copy.ConfigMap = clonePointer(value.ConfigMap)
	return &copy
}

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
	if !path.IsAbs(ca.Filename) || path.Clean(ca.Filename) != ca.Filename || ca.Filename == "/" || strings.ContainsAny(ca.Filename, "\r\n\x00") {
		return fmt.Errorf("%s.filename must be a clean absolute file path", name)
	}
	return nil
}

func (ref CAConfigMap) id() string {
	digest := sha256.Sum256([]byte(ref.Name + "\x00" + ref.Key))
	return hex.EncodeToString(digest[:16])
}

func (ca *TrustedCA) filename() string {
	if ca == nil {
		return systemCABundle
	}
	if ca.ConfigMap != nil {
		return path.Join(caDirectory, ca.ConfigMap.id(), "ca.crt")
	}
	return ca.Filename
}

func (c Config) caMounts() []CAConfigMap {
	var mounts []CAConfigMap
	seen := map[CAConfigMap]bool{}
	add := func(ca *TrustedCA) {
		if ca != nil && ca.ConfigMap != nil && !seen[*ca.ConfigMap] {
			mounts = append(mounts, *ca.ConfigMap)
			seen[*ca.ConfigMap] = true
		}
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil && authenticatorUsed(c.Servers, authenticator.Name) {
			add(authenticator.JWT.JWKS.TrustedCA)
		}
	}
	for _, api := range c.APIs {
		if api.Upstream.TLSConfig != nil {
			add(api.Upstream.TLSConfig.TrustedCA)
		}
	}
	return mounts
}

func verifiedTLS(identity string, ca *TrustedCA, alpn []string) (*core.TransportSocket, error) {
	sanType := tls.SubjectAltNameMatcher_DNS
	sni := identity
	if ip := net.ParseIP(identity); ip != nil {
		sanType = tls.SubjectAltNameMatcher_IP_ADDRESS
		sni = ""
		identity = ip.String()
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
				TrustedCa: fileDataSource(ca.filename()),
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
	return &core.TransportSocket{Name: "envoy.transport_sockets.tls", ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: packed}}, nil
}
