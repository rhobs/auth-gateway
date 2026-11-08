package config

import (
	"testing"
	"time"

	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
)

func TestUpstreamTLSAndExplicitProtocols(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	ca := &TrustedCA{ConfigMap: &CAConfigMap{Name: "shared-ca", Key: "ca.pem"}}
	c.Authenticators[0].JWT.JWKS.TrustedCA = ca
	c.APIs[0].Upstream = Upstream{Address: "192.0.2.2", Port: 443, HTTPProtocol: "http2", HTTP2: &HTTP2Options{MaxConcurrentStreams: new(uint32(8)), InitialStreamWindowSize: new(uint32(65535))}, ConnectTimeout: duration(2 * time.Second), PerConnectionBufferLimitBytes: new(uint32(65536)), TLSConfig: &UpstreamTLS{ServerName: "backend.example.test", TrustedCA: ca}}
	second := c.APIs[0]
	second.Name = "ip-backend"
	second.Upstream = Upstream{Address: "2001:db8::1", Port: 443, TLSConfig: &UpstreamTLS{TrustedCA: ca}}
	c.APIs = append(c.APIs, second)
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(r.ConfigMap.Data["envoy.yaml"]))
	for i, cluster := range b.StaticResources.Clusters[:2] {
		var protocol upstreamhttp.HttpProtocolOptions
		if err := cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&protocol); err != nil {
			t.Fatal(err)
		}
		if protocol.RetryPolicy != nil {
			t.Fatal("retries emitted")
		}
		var transport tls.UpstreamTlsContext
		if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		validation := transport.CommonTlsContext.GetValidationContext()
		if validation.TrustedCa.GetFilename() != ca.filename() {
			t.Fatalf("CA path = %v", validation)
		}
		if i == 0 {
			if protocol.GetExplicitHttpConfig().GetHttp2ProtocolOptions().MaxConcurrentStreams.Value != 8 || transport.Sni != "backend.example.test" || transport.CommonTlsContext.AlpnProtocols[0] != "h2" || cluster.ConnectTimeout.AsDuration() != 2*time.Second || cluster.PerConnectionBufferLimitBytes.Value != 65536 {
				t.Fatalf("HTTP/2 TLS upstream = %v / %v", cluster, &transport)
			}
		} else if protocol.GetExplicitHttpConfig().GetHttpProtocolOptions() == nil || transport.Sni != "" || validation.MatchTypedSubjectAltNames[0].SanType != tls.SubjectAltNameMatcher_IP_ADDRESS || validation.MatchTypedSubjectAltNames[0].Matcher.GetExact() != "2001:db8::1" {
			t.Fatalf("HTTP/1 IP TLS upstream = %v / %v", cluster, &transport)
		}
	}
	count := 0
	for _, v := range r.Deployment.Spec.Template.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == "shared-ca" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared JWKS/backend CA mount count = %d", count)
	}
}

func TestCircuitBreakerConfigAppliesToJWKSCluster(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].JWT.JWKS.CircuitBreakers = &CircuitBreakerConfig{
		MaxConnections: new(uint32(3)), MaxRequests: new(uint32(0)), MaxRetries: new(uint32(7)),
	}
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, []byte(resources.ConfigMap.Data[envoyConfigFilename]))
	name := jwksClusterName(c.Authenticators[0].Name)
	for _, cluster := range bootstrap.StaticResources.Clusters {
		if cluster.Name != name {
			continue
		}
		if len(cluster.CircuitBreakers.Thresholds) != 1 {
			t.Fatalf("JWKS circuit breaker thresholds = %v, want one threshold", cluster.CircuitBreakers.Thresholds)
		}
		limits := cluster.CircuitBreakers.Thresholds[0]
		if limits.MaxConnections.Value != 3 || limits.MaxPendingRequests.Value != 1024 ||
			limits.MaxRequests.Value != 0 || limits.MaxRetries.Value != 7 {
			t.Fatalf("JWKS circuit breaker limits = %v", limits)
		}
		return
	}
	t.Fatalf("JWKS cluster %q not found", name)
}
