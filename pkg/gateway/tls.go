package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	mtlsMetadataNamespace      = "auth_gateway.mtls"
	mtlsFingerprintMetadataKey = "fingerprint"
	mtlsURIMetadataKey         = "uri_san"
	mtlsDNSMetadataKey         = "dns_san"
	mtlsFingerprintHeaderName  = "x-auth-gateway-mtls-fingerprint"
	mtlsURIHeaderName          = "x-auth-gateway-mtls-uri-san"
	mtlsDNSHeaderName          = "x-auth-gateway-mtls-dns-san"
	// Request-control and peer filters remove client values and overwrite this
	// header from TLS state. Keep the matcher below Envoy's RE2 size limit.
	mtlsFingerprintPattern      = "^[0-9A-Fa-f:]+$"
	googleHTTP11ALPN            = "http/1.1"
	systemCABundle              = "/etc/ssl/certs/ca-certificates.crt"
	tlsTransportSocketName      = "envoy.transport_sockets.tls"
	caCertificateFilename       = "ca.crt"
	caDirectory                 = TrustedCADirectory
	tlsInspectorFilterName      = "envoy.filters.listener.tls_inspector"
	defaultServerTLSCertificate = "/etc/auth-gateway-tls/tls.crt"
	defaultServerTLSPrivateKey  = "/etc/auth-gateway-tls/tls.key"
	tlsCertificateSecretKey     = "tls.crt"
	tlsPrivateKeySecretKey      = "tls.key"
	serverTLSSecretDirectory    = "/etc"
)

type serverTLSMount struct {
	serverIndex int
	config      gatewayapi.ServerTLS
}

func tlsMounts(c gatewayapi.Config) []serverTLSMount {
	var mounts []serverTLSMount
	seen := make(map[gatewayapi.ServerTLS]struct{})
	for i, server := range c.Servers {
		if server.TLSConfig == nil {
			continue
		}
		binding := *server.TLSConfig
		identity := binding
		identity.MTLS = nil
		if _, exists := seen[identity]; exists {
			continue
		}
		seen[identity] = struct{}{}
		mounts = append(mounts, serverTLSMount{serverIndex: i, config: binding})
	}
	return mounts
}

func validateTLSMounts(c gatewayapi.Config) error {
	mounts := tlsMounts(c)
	for i, mount := range mounts {
		name := fmt.Sprintf("servers[%d].tls_config", mount.serverIndex)
		if mount.config.Secret == "" {
			return fmt.Errorf("%s.secret is required when generating Kubernetes resources", name)
		}
		directory := path.Dir(mount.config.Certificate)
		for _, reserved := range []string{configDirectory, collectorConfigDirectory, caDirectory} {
			if directoriesOverlap(directory, reserved) {
				return fmt.Errorf("%s certificate directory %q overlaps configuration directory %q", name, directory, reserved)
			}
		}
		for _, previous := range mounts[:i] {
			if directoriesOverlap(directory, path.Dir(previous.config.Certificate)) {
				return fmt.Errorf("%s certificate directory overlaps servers[%d].tls_config", name, previous.serverIndex)
			}
		}
	}
	return nil
}

func cloneMTLSAuthenticator(m gatewayapi.MTLSAuthenticator) gatewayapi.MTLSAuthenticator {
	m.TrustedCA = cloneConfigPointer(m.TrustedCA, cloneTrustedCA)
	return m
}

func withDefaultsServerTLS(s gatewayapi.ServerTLS) gatewayapi.ServerTLS {
	certificate, privateKey := defaultServerTLSCertificate, defaultServerTLSPrivateKey
	if s.Secret != "" {
		certificate = path.Join(serverTLSSecretDirectory, s.Secret, tlsCertificateSecretKey)
		privateKey = path.Join(serverTLSSecretDirectory, s.Secret, tlsPrivateKeySecretKey)
	}
	if s.Certificate == "" {
		s.Certificate = certificate
	}
	if s.PrivateKey == "" {
		s.PrivateKey = privateKey
	}
	return s
}

func validateServerTLS(name string, serverTLS gatewayapi.ServerTLS) error {
	for _, file := range []struct {
		Name  string
		Value string
	}{
		{Name: "certificate", Value: serverTLS.Certificate},
		{Name: "private_key", Value: serverTLS.PrivateKey},
	} {
		if !path.IsAbs(file.Value) || path.Clean(file.Value) != file.Value || file.Value == "/" || strings.ContainsAny(file.Value, invalidControlCharacters) {
			return fmt.Errorf("%s.%s must be a clean absolute file path", name, file.Name)
		}
	}
	if path.Dir(serverTLS.Certificate) != path.Dir(serverTLS.PrivateKey) {
		return fmt.Errorf("%s.certificate and %s.private_key must be in the same directory", name, name)
	}
	if path.Base(serverTLS.Certificate) == path.Base(serverTLS.PrivateKey) {
		return fmt.Errorf("%s.certificate and %s.private_key must have different file names", name, name)
	}
	return nil
}

func directoriesOverlap(a, b string) bool {
	return a == b || a == "/" || b == "/" ||
		strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func cloneServerTLS(s gatewayapi.ServerTLS) gatewayapi.ServerTLS {
	s.MTLS = clonePointer(s.MTLS)
	return s
}

func serverTLSSecretName(index int) string {
	return "gateway_server_" + strconv.Itoa(index)
}

func serverTLSResourceFilename(index int) string {
	return "server-certificate-" + strconv.Itoa(index) + ".yaml"
}

func clientCASecretName(index int) string {
	return "gateway_client_ca_" + strconv.Itoa(index)
}

func clientCAResourceFilename(index int) string {
	return "client-ca-" + strconv.Itoa(index) + ".yaml"
}

func validateTrustedCA(name string, ca *gatewayapi.TrustedCA, kubernetes bool) error {
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
	if !path.IsAbs(ca.Filename) || path.Clean(ca.Filename) != ca.Filename || ca.Filename == "/" || strings.ContainsAny(ca.Filename, invalidControlCharacters) {
		return fmt.Errorf("%s.filename must be a clean absolute file path", name)
	}
	return nil
}

func cloneTrustedCA(ca gatewayapi.TrustedCA) gatewayapi.TrustedCA {
	ca.ConfigMap = clonePointer(ca.ConfigMap)
	return ca
}

func idCAConfigMap(ref gatewayapi.CAConfigMap) string {
	digest := sha256.Sum256([]byte(ref.Name + "\x00" + ref.Key))
	return hex.EncodeToString(digest[:16])
}

// FilePath returns the absolute Envoy path used for this CA ConfigMap entry.
func filePathCAConfigMap(ref gatewayapi.CAConfigMap) string {
	return path.Join(TrustedCADirectory, idCAConfigMap(ref), caCertificateFilename)
}

func filenameTrustedCA(ca gatewayapi.TrustedCA) string {
	if ca.ConfigMap != nil {
		return filePathCAConfigMap(*ca.ConfigMap)
	}
	return ca.Filename
}

func clientCASecret(m gatewayapi.MTLSAuthenticator, index int) *tls.Secret {
	filename := filenameTrustedCA(*m.TrustedCA)
	return &tls.Secret{
		Name: clientCASecretName(index),
		Type: &tls.Secret_ValidationContext{ValidationContext: &tls.CertificateValidationContext{
			TrustedCa:        fileDataSource(filename),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(filename)},
		}},
	}
}

func serverTLSSecret(config gatewayapi.ServerTLS, index int) *tls.Secret {
	return &tls.Secret{
		Name: serverTLSSecretName(index),
		Type: &tls.Secret_TlsCertificate{TlsCertificate: &tls.TlsCertificate{
			CertificateChain: fileDataSource(config.Certificate),
			PrivateKey:       fileDataSource(config.PrivateKey),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(config.Certificate)},
		}},
	}
}

func serverTLSTransportSocket(index int, mtls *gatewayapi.MTLSAuthenticator) (*core.TransportSocket, error) {
	context := &tls.DownstreamTlsContext{CommonTlsContext: &tls.CommonTlsContext{
		TlsParams: &tls.TlsParameters{
			TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
			TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
		},
		AlpnProtocols: []string{"h2", googleHTTP11ALPN},
		TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{{
			Name:      serverTLSSecretName(index),
			SdsConfig: serverTLSSecretConfigSource(index),
		}},
	}}
	if mtls != nil {
		context.CommonTlsContext.ValidationContextType = &tls.CommonTlsContext_ValidationContextSdsSecretConfig{ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
			Name: clientCASecretName(index), SdsConfig: fileConfigSource(path.Join(EnvoyConfigDirectory, clientCAResourceFilename(index))),
		}}
		context.RequireClientCertificate = wrapperspb.Bool(true)
		context.DisableStatefulSessionResumption = true
		context.SessionTicketKeysType = &tls.DownstreamTlsContext_DisableStatelessSessionResumption{DisableStatelessSessionResumption: true}
	}
	config, err := packEnvoy(context)
	if err != nil {
		return nil, err
	}
	return &core.TransportSocket{
		Name:       tlsTransportSocketName,
		ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: config},
	}, nil
}

func serverTLSSecretConfigSource(index int) *core.ConfigSource {
	return fileConfigSource(path.Join(configDirectory, serverTLSResourceFilename(index)))
}

func verifiedTLS(identity string, ca *gatewayapi.TrustedCA, alpn []string) (*core.TransportSocket, error) {
	sanType := tls.SubjectAltNameMatcher_DNS
	sni := identity
	if ip := net.ParseIP(identity); ip != nil {
		sanType = tls.SubjectAltNameMatcher_IP_ADDRESS
		sni = ""
		identity = ip.String()
	}
	caFilename := systemCABundle
	if ca != nil {
		caFilename = filenameTrustedCA(*ca)
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

func generateListenerFilters(c resolvedConfig) ([]*listener.ListenerFilter, error) {
	if !hasHTTPS(c.Config) {
		return nil, nil
	}
	inspectorConfig, err := packEnvoy(&inspector.TlsInspector{})
	if err != nil {
		return nil, fmt.Errorf("encode TLS inspector: %w", err)
	}
	return []*listener.ListenerFilter{{
		Name:       tlsInspectorFilterName,
		ConfigType: &listener.ListenerFilter_TypedConfig{TypedConfig: inspectorConfig},
	}}, nil
}
