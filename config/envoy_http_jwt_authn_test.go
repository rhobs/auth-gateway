package config

import (
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

func TestJWTProviderClustersAndTrust(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, generated.StaticResources.Listeners[0].FilterChains[0])

	var jwtConfig jwt.JwtAuthentication
	var jwtFilter *hcm.HttpFilter
	for _, filter := range manager.HttpFilters {
		if filter.Name == jwtAuthnFilterName {
			jwtFilter = filter
			break
		}
	}
	if jwtFilter == nil {
		t.Fatal("JWT filter is missing")
	}
	if err := jwtFilter.GetTypedConfig().UnmarshalTo(&jwtConfig); err != nil {
		t.Fatal(err)
	}
	if len(jwtConfig.Providers) != 2 || len(jwtConfig.RequirementMap) != 2 {
		t.Fatalf("JWT provider/requirement counts = %d/%d", len(jwtConfig.Providers), len(jwtConfig.RequirementMap))
	}
	for name, issuer := range map[string]string{
		"issuer-one": "https://issuer-one.jwt.test",
		"issuer-two": "https://issuer-two.jwt.test",
	} {
		provider := jwtConfig.Providers[name]
		if provider == nil || provider.Issuer != issuer || provider.PayloadInMetadata != name ||
			!provider.RequireExpiration || provider.Forward || len(provider.FromHeaders) != 1 ||
			provider.FromHeaders[0].Name != "Authorization" || provider.FromHeaders[0].ValuePrefix != "Bearer " {
			t.Fatalf("JWT provider %q = %#v", name, provider)
		}
		remote := provider.GetRemoteJwks()
		if remote == nil || remote.HttpUri == nil || remote.HttpUri.GetCluster() != jwksClusterName(name) {
			t.Fatalf("JWT provider %q has no dedicated JWKS cluster", name)
		}
		if remote.CacheDuration == nil {
			t.Fatalf("JWT provider %q has no JWKS cache duration", name)
		}
		if got, want := remote.CacheDuration.AsDuration(), 5*time.Minute; got != want {
			t.Fatalf("JWT provider %q cache duration = %s, want default %s", name, got, want)
		}
	}
	if jwtConfig.RequirementMap[serverJWTRequirementName(1)].GetProviderName() != "issuer-one" {
		t.Fatalf("issuer-restricted server JWT requirement = %#v", jwtConfig.RequirementMap[serverJWTRequirementName(1)])
	}

	clusters := make(map[string]*cluster.Cluster, len(generated.StaticResources.Clusters))
	for _, item := range generated.StaticResources.Clusters {
		clusters[item.Name] = item
	}
	for _, name := range []string{"issuer-one", "issuer-two"} {
		jwks := clusters[jwksClusterName(name)]
		if jwks == nil || jwks.TransportSocket == nil {
			t.Fatalf("missing TLS JWKS cluster for %q", name)
		}
		wantFamily := cluster.Cluster_V4_ONLY
		if name == "issuer-two" {
			wantFamily = cluster.Cluster_V6_ONLY
		}
		if got := jwks.GetDnsLookupFamily(); got != wantFamily {
			t.Fatalf("JWKS cluster %q DNS lookup family = %s, want %s", name, got, wantFamily)
		}
		var upstream tls.UpstreamTlsContext
		if err := jwks.TransportSocket.GetTypedConfig().UnmarshalTo(&upstream); err != nil {
			t.Fatal(err)
		}
		if upstream.GetSni() == "" || upstream.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() == "" {
			t.Fatalf("JWKS TLS validation is not enabled for %q", name)
		}
	}
	if got, want := len(generated.StaticResources.Clusters), len(c.APIs)+len(jwtConfig.Providers); got != want {
		t.Fatalf("upstream/JWKS cluster count = %d, want %d", got, want)
	}
}
