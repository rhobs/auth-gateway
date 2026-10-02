package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

func TestGenerateJWTAuthenticationMatchesGolden(t *testing.T) {
	c, err := Load(bytes.NewReader([]byte(readFixture(t, "jwt-auth.yaml"))))
	if err != nil {
		t.Fatal(err)
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "kubernetes", "jwt-envoy.yaml.golden")
	if *updateGolden {
		if err := os.WriteFile(path, files["envoy.yaml"], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(files["envoy.yaml"], want) {
		t.Fatal("generated JWT Envoy config does not match the golden file")
	}

	bootstrapConfig := decodeBootstrap(t, files["envoy.yaml"])
	if len(bootstrapConfig.StaticResources.Clusters) != len(c.APIs)+len(c.Authenticators) {
		t.Fatalf("cluster count = %d", len(bootstrapConfig.StaticResources.Clusters))
	}
	clusters := map[string]*cluster.Cluster{}
	for _, item := range bootstrapConfig.StaticResources.Clusters {
		clusters[item.Name] = item
	}
	for _, name := range []string{"issuer-one", "issuer-two"} {
		jwks := clusters[jwksClusterName(name)]
		if jwks == nil || jwks.TransportSocket == nil {
			t.Fatalf("missing TLS JWKS cluster for %q", name)
		}
		var upstream tls.UpstreamTlsContext
		if err := jwks.TransportSocket.GetTypedConfig().UnmarshalTo(&upstream); err != nil {
			t.Fatal(err)
		}
		if upstream.GetSni() == "" || upstream.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() == "" {
			t.Fatalf("JWKS TLS validation is not enabled for %q", name)
		}
	}
	generatedListener := bootstrapConfig.StaticResources.Listeners[0]
	for _, chain := range generatedListener.FilterChains {
		var manager hcm.HttpConnectionManager
		if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
			t.Fatal(err)
		}
		if len(manager.HttpFilters) != 2 || manager.HttpFilters[0].Name != "envoy.filters.http.jwt_authn" || manager.HttpFilters[1].Name != "envoy.filters.http.router" {
			t.Fatalf("HTTP filter order = %v", manager.HttpFilters)
		}
		var jwtConfig jwt.JwtAuthentication
		if err := manager.HttpFilters[0].GetTypedConfig().UnmarshalTo(&jwtConfig); err != nil {
			t.Fatal(err)
		}
		if len(jwtConfig.Providers) != 2 || len(jwtConfig.RequirementMap) != 1 {
			t.Fatalf("JWT providers/requirements = %d/%d", len(jwtConfig.Providers), len(jwtConfig.RequirementMap))
		}
		for _, provider := range jwtConfig.Providers {
			if !provider.RequireExpiration || provider.Forward || provider.PayloadInMetadata == "" {
				t.Fatalf("JWT provider requirements = %#v", provider)
			}
		}
		for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
			if host.Name == "public.example.test" {
				if len(host.TypedPerFilterConfig) != 0 {
					t.Fatalf("public virtual host %q has JWT requirements", host.Name)
				}
				continue
			}
			if len(host.TypedPerFilterConfig) != 1 {
				t.Fatalf("virtual host %q lacks a scoped JWT requirement", host.Name)
			}
			var requirement jwt.PerRouteConfig
			if err := host.TypedPerFilterConfig["envoy.filters.http.jwt_authn"].UnmarshalTo(&requirement); err != nil {
				t.Fatal(err)
			}
			if requirement.GetRequirementName() == "" {
				t.Fatalf("virtual host %q JWT requirement is empty", host.Name)
			}
		}
	}
}
