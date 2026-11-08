package gateway

import (
	"strings"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestJWKSFetchTimeoutDefaultsForNull(t *testing.T) {
	c, err := Load(strings.NewReader(readFixture(t, "jwks-duration-null.yaml")))
	if err != nil || *c.Authenticators[0].JWT.JWKS.FetchTimeout != gatewayapi.Duration(5*time.Second) {
		t.Fatalf("null fetch timeout default: %v", err)
	}
}

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

func TestJWKSValidationIncludesUnusedProviders(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*gatewayapi.Config)
		field string
	}{
		{"zero", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(0) }, ".cache_duration"},
		{"negative Go duration", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(-time.Second) }, ".cache_duration"},
		{"connect exceeds fetch", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.ConnectTimeout = duration(6 * time.Second) }, ".connect_timeout"},
		{"empty CA", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{} }, ".trusted_ca"},
		{"both sources", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "/ca.pem", ConfigMap: &gatewayapi.CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca"},
		{"ConfigMap without Kubernetes", func(c *gatewayapi.Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca.config_map"},
		{"bad ConfigMap name", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "bad/name", Key: "ca.pem"}}
		}, ".trusted_ca.config_map.name"},
		{"bad key", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "ca", Key: "../ca.pem"}}
		}, ".trusted_ca.config_map.key"},
		{"relative file", func(c *gatewayapi.Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "ca.pem"}
		}, ".trusted_ca.filename"},
		{"relative file in Kubernetes", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "ca.pem"}
		}, ".trusted_ca.filename"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadConfigCase(t, "jwt-auth")
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
			tt.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks"+tt.field) {
				t.Fatalf("validation = %v", err)
			}
		})
	}
	c := loadConfigCase(t, "jwt-auth")
	c.Kubernetes = nil
	c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "/etc/company/ca.crt"}
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	c = loadConfigCase(t, "server-tls")
	c.Servers[1].TLSConfig.Certificate = caDirectory + "/roots/tls.crt"
	c.Servers[1].TLSConfig.PrivateKey = caDirectory + "/roots/tls.key"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), caDirectory) {
		t.Fatalf("reserved CA mount tree: %v", err)
	}
}
