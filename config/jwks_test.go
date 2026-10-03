package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"go.yaml.in/yaml/v3"
)

func duration(value time.Duration) *Duration { return new(Duration(value)) }

func TestDurationYAMLContract(t *testing.T) {
	for _, value := range []string{"250ms", "5s", "5m", "1.5ms", "0s"} {
		var parsed Duration
		if err := yaml.Unmarshal([]byte(value), &parsed); err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
		encoded, err := yaml.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip Duration
		if err := yaml.Unmarshal(encoded, &roundtrip); err != nil || parsed != roundtrip {
			t.Fatalf("duration roundtrip %q: %v, %v", value, roundtrip, err)
		}
	}
	input := readFixture(t, "jwt-auth/config.yaml")
	for _, value := range []string{"5", `""`, "-1s", "500us", "999999999999h", "[5s]"} {
		text := strings.Replace(input, "      jwks:\n", "      jwks:\n        fetch_timeout: "+value+"\n", 1)
		if _, err := Load(strings.NewReader(text)); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks.fetch_timeout") {
			t.Errorf("duration %s: got %v, want full field path", value, err)
		}
	}
	for _, value := range []string{"null", "5s"} {
		text := strings.Replace(input, "      jwks:\n", "      jwks:\n        fetch_timeout: "+value+"\n", 1)
		c, err := Load(strings.NewReader(text))
		if err != nil || *c.Authenticators[0].JWT.JWKS.FetchTimeout != Duration(5*time.Second) {
			t.Fatalf("omission/null default: %v", err)
		}
	}
	text := strings.Replace(input, "      jwks:\n        uri:", "      jwks_uri:", 1)
	if _, err := Load(strings.NewReader(text)); err == nil || !strings.Contains(err.Error(), "field jwks_uri not found") {
		t.Fatalf("old jwks_uri accepted: %v", err)
	}
}

func TestJWKSTransportAndTrust(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	ca := &TrustedCA{ConfigMap: &CAConfigMap{Name: "issuer-ca", Key: "roots.pem"}}
	for i := range c.Authenticators {
		c.Authenticators[i].JWT.JWKS.TrustedCA = ca
	}
	j := &c.Authenticators[0].JWT.JWKS
	j.URI = "https://192.0.2.1:9443/keys"
	j.CacheDuration = duration(15 * time.Second)
	j.FetchTimeout = duration(2 * time.Second)
	j.ConnectTimeout = duration(500 * time.Millisecond)
	j.CircuitBreakers = &CircuitBreakerConfig{MaxConnections: new(uint32(3)), MaxRequests: new(uint32(0)), MaxRetries: new(uint32(7))}
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(r.ConfigMap.Data["envoy.yaml"]))
	manager := decodeHTTPManager(t, b.StaticResources.Listeners[0].FilterChains[0])
	var providers jwt.JwtAuthentication
	for _, f := range manager.HttpFilters {
		if f.Name == "envoy.filters.http.jwt_authn" {
			if err := f.GetTypedConfig().UnmarshalTo(&providers); err != nil {
				t.Fatal(err)
			}
		}
	}
	remote := providers.Providers[c.Authenticators[0].Name].GetRemoteJwks()
	if remote.CacheDuration.AsDuration() != 15*time.Second || remote.HttpUri.Timeout.AsDuration() != 2*time.Second || remote.AsyncFetch != nil || remote.RetryPolicy != nil {
		t.Fatalf("remote JWKS controls = %v", remote)
	}
	for _, cluster := range b.StaticResources.Clusters {
		if !strings.HasPrefix(cluster.Name, "jwks-") {
			continue
		}
		var transport tls.UpstreamTlsContext
		if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		validation := transport.CommonTlsContext.GetValidationContext()
		if validation.TrustedCa.GetFilename() != ca.filename() || len(validation.MatchTypedSubjectAltNames) != 1 {
			t.Fatalf("trust = %v", validation)
		}
		san := validation.MatchTypedSubjectAltNames[0]
		if cluster.Name == jwksClusterName(c.Authenticators[0].Name) {
			if transport.Sni != "" || san.SanType != tls.SubjectAltNameMatcher_IP_ADDRESS || san.Matcher.GetExact() != "192.0.2.1" {
				t.Fatalf("IP identity = %v", &transport)
			}
			limits := cluster.CircuitBreakers.Thresholds[0]
			if cluster.ConnectTimeout.AsDuration() != 500*time.Millisecond || limits.MaxConnections.Value != 3 || limits.MaxRequests.Value != 0 || limits.MaxRetries.Value != 7 {
				t.Fatalf("JWKS limits = %v", cluster)
			}
		} else if transport.Sni == "" || san.SanType != tls.SubjectAltNameMatcher_DNS || san.Matcher.GetExact() != transport.Sni {
			t.Fatalf("DNS identity = %v", &transport)
		}
	}
	volumes := 0
	for _, volume := range r.Deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == ca.ConfigMap.Name {
			volumes++
			if len(volume.ConfigMap.Items) != 1 || volume.ConfigMap.Items[0].Key != "roots.pem" || volume.ConfigMap.Items[0].Path != "ca.crt" {
				t.Fatalf("CA projection = %v", volume)
			}
		}
	}
	if volumes != 1 {
		t.Fatalf("CA mount count = %d, want deduplicated mount", volumes)
	}
	for _, mount := range r.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts {
		if strings.HasPrefix(mount.MountPath, caDirectory) && (!mount.ReadOnly || mount.SubPath != "") {
			t.Fatalf("CA mount = %v", mount)
		}
	}
	before, _ := yaml.Marshal(c)
	for _, check := range []func(Config) error{Config.Validate, func(c Config) error { _, err := Generate(c); return err }, func(c Config) error { _, err := GenerateKubernetes(c); return err }} {
		if err := check(c); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := yaml.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("generation mutated caller configuration")
	}
	copy := c.withDefaults()
	copy.Authenticators[0].JWT.JWKS.TrustedCA.ConfigMap.Key = "changed"
	*copy.Authenticators[0].JWT.JWKS.CacheDuration = Duration(time.Minute)
	*copy.Authenticators[0].JWT.JWKS.CircuitBreakers.MaxConnections = 99
	if ca.ConfigMap.Key != "roots.pem" || *j.CacheDuration != Duration(15*time.Second) || *j.CircuitBreakers.MaxConnections != 3 {
		t.Fatal("defaulting retained JWKS aliases")
	}
	second, err := GenerateKubernetes(c)
	if err != nil || !reflect.DeepEqual(r, second) {
		t.Fatalf("generation is not deterministic: %v", err)
	}
}

func TestJWKSValidationIncludesUnusedProviders(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*Config)
		field string
	}{
		{"zero", func(c *Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(0) }, ".cache_duration"},
		{"negative Go duration", func(c *Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(-time.Second) }, ".cache_duration"},
		{"connect exceeds fetch", func(c *Config) { c.Authenticators[0].JWT.JWKS.ConnectTimeout = duration(6 * time.Second) }, ".connect_timeout"},
		{"empty CA", func(c *Config) { c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{} }, ".trusted_ca"},
		{"both sources", func(c *Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "/ca.pem", ConfigMap: &CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca"},
		{"file in Kubernetes", func(c *Config) { c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "/ca.pem"} }, ".trusted_ca.filename"},
		{"ConfigMap without Kubernetes", func(c *Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca.config_map"},
		{"bad ConfigMap name", func(c *Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "bad/name", Key: "ca.pem"}}
		}, ".trusted_ca.config_map.name"},
		{"bad key", func(c *Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "ca", Key: "../ca.pem"}}
		}, ".trusted_ca.config_map.key"},
		{"relative file", func(c *Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "ca.pem"}
		}, ".trusted_ca.filename"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadConfigCase(t, "jwt-auth")
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
			tt.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks"+tt.field) {
				t.Fatalf("validation = %v", err)
			}
		})
	}
	c := loadConfigCase(t, "jwt-auth")
	c.Kubernetes = nil
	c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "/etc/company/ca.crt"}
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	c = loadConfigCase(t, "server-tls")
	c.Servers[1].TLSConfig.Certificate = caDirectory + "/roots/tls.crt"
	c.Servers[1].TLSConfig.PrivateKey = caDirectory + "/roots/tls.key"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), caDirectory) {
		t.Fatalf("reserved CA mount tree: %v", err)
	}
}
