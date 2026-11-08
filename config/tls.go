package config

import (
	"net"
	"path"
	"strconv"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	googleHTTP11ALPN       = "http/1.1"
	systemCABundle         = "/etc/ssl/certs/ca-certificates.crt"
	tlsTransportSocketName = "envoy.transport_sockets.tls"
)

func serverTLSSecretName(index int) string {
	return "gateway_server_" + strconv.Itoa(index)
}

func serverTLSResourceFilename(index int) string {
	return "server-certificate-" + strconv.Itoa(index) + ".yaml"
}

func serverTLSTransportSocket(index int, mtls *MTLSAuthenticator, requireClientCertificate bool) (*core.TransportSocket, error) {
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
		context.RequireClientCertificate = wrapperspb.Bool(requireClientCertificate)
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

func clientCASecretName(index int) string {
	return "gateway_client_ca_" + strconv.Itoa(index)
}

func clientCAResourceFilename(index int) string {
	return "client-ca-" + strconv.Itoa(index) + ".yaml"
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
