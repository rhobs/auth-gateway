package envoy

import (
	"net"
	"path"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func clientCASecret(m gatewayapi.MTLSAuthenticator, index int) *tls.Secret {
	filename := configuration.FilenameTrustedCA(*m.TrustedCA)
	return &tls.Secret{
		Name: configuration.ClientCASecretName(index),
		Type: &tls.Secret_ValidationContext{ValidationContext: &tls.CertificateValidationContext{
			TrustedCa:        fileDataSource(filename),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(filename)},
		}},
	}
}

func serverTLSSecret(config gatewayapi.ServerTLS, index int) *tls.Secret {
	return &tls.Secret{
		Name: configuration.ServerTLSSecretName(index),
		Type: &tls.Secret_TlsCertificate{TlsCertificate: &tls.TlsCertificate{
			CertificateChain: fileDataSource(config.Certificate),
			PrivateKey:       fileDataSource(config.PrivateKey),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(config.Certificate)},
		}},
	}
}

func serverTLSTransportSocket(index int, mtls *gatewayapi.MTLSAuthenticator, requireClientCertificate bool) (*core.TransportSocket, error) {
	context := &tls.DownstreamTlsContext{CommonTlsContext: &tls.CommonTlsContext{
		TlsParams: &tls.TlsParameters{
			TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
			TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
		},
		AlpnProtocols: []string{"h2", configuration.GoogleHTTP11ALPN},
		TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{{
			Name:      configuration.ServerTLSSecretName(index),
			SdsConfig: serverTLSSecretConfigSource(index),
		}},
	}}
	if mtls != nil {
		context.CommonTlsContext.ValidationContextType = &tls.CommonTlsContext_ValidationContextSdsSecretConfig{ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
			Name: configuration.ClientCASecretName(index), SdsConfig: fileConfigSource(path.Join(configuration.EnvoyConfigDirectory, configuration.ClientCAResourceFilename(index))),
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
		Name:       configuration.TlsTransportSocketName,
		ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: config},
	}, nil
}

func serverTLSSecretConfigSource(index int) *core.ConfigSource {
	return fileConfigSource(path.Join(configuration.ConfigDirectory, configuration.ServerTLSResourceFilename(index)))
}

func verifiedTLS(identity string, ca *gatewayapi.TrustedCA, alpn []string) (*core.TransportSocket, error) {
	sanType := tls.SubjectAltNameMatcher_DNS
	sni := identity
	if ip := net.ParseIP(identity); ip != nil {
		sanType = tls.SubjectAltNameMatcher_IP_ADDRESS
		sni = ""
		identity = ip.String()
	}
	caFilename := configuration.SystemCABundle
	if ca != nil {
		caFilename = configuration.FilenameTrustedCA(*ca)
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
	return &core.TransportSocket{Name: configuration.TlsTransportSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: packed}}, nil
}
