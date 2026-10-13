package config

import (
	"path"
	"slices"
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

func TestGenerateMTLSClientCAAndCertificateRequirements(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(files.ClientCAResources), 4; got != want {
		t.Fatalf("client CA resource count = %d, want %d", got, want)
	}

	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	chains := bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains()
	wantRequired := map[string]bool{
		"mtls.gateway.test":  true,
		"mixed.gateway.test": false,
		"all.gateway.test":   true,
		"trust.gateway.test": true,
	}
	for serverIndex, server := range c.Servers {
		authenticator, selected := c.serverMTLSAuthenticator(server)
		if !selected {
			continue
		}
		caPath := path.Join(EnvoyConfigDirectory, clientCAResourceFilename(serverIndex))
		resource := generatedContentsByPath(t, files, caPath)
		secret := decodeTLSSecret(t, resource)
		validation := secret.GetValidationContext()
		if validation == nil {
			t.Fatalf("client CA resource %q has no validation context", caPath)
		}
		if got, want := secret.GetName(), clientCASecretName(serverIndex); got != want {
			t.Errorf("client CA secret name = %q, want %q", got, want)
		}
		caFilename := authenticator.MTLS.TrustedCA.filename()
		if got := validation.GetTrustedCa().GetFilename(); got != caFilename {
			t.Errorf("trusted CA filename = %q, want %q", got, caFilename)
		}
		if got := validation.GetWatchedDirectory().GetPath(); got != path.Dir(caFilename) {
			t.Errorf("trusted CA watched directory = %q, want %q", got, path.Dir(caFilename))
		}

		var chain *listener.FilterChain
		for _, candidate := range chains {
			for _, hostname := range candidate.GetFilterChainMatch().GetServerNames() {
				if hostname == server.Hostname {
					chain = candidate
				}
			}
		}
		if chain == nil {
			t.Fatalf("TLS filter chain for %q is missing", server.Hostname)
		}
		var downstream tls.DownstreamTlsContext
		if err := chain.GetTransportSocket().GetTypedConfig().UnmarshalTo(&downstream); err != nil {
			t.Fatal(err)
		}
		if got := downstream.GetRequireClientCertificate(); got == nil || got.GetValue() != wantRequired[server.Hostname] {
			t.Errorf("%s require_client_certificate = %v, want %t", server.Hostname, got, wantRequired[server.Hostname])
		}
		clientCA := downstream.GetCommonTlsContext().GetValidationContextSdsSecretConfig()
		if clientCA == nil {
			t.Fatalf("%s has no client CA SDS reference", server.Hostname)
		}
		if got, want := clientCA.GetName(), clientCASecretName(serverIndex); got != want {
			t.Errorf("%s client CA SDS name = %q, want %q", server.Hostname, got, want)
		}
		if got, want := clientCA.GetSdsConfig().GetPathConfigSource().GetPath(), caPath; got != want {
			t.Errorf("%s client CA SDS path = %q, want %q", server.Hostname, got, want)
		}
	}
}

func TestMTLSAllOfSharedAttributesAreCheckedAfterAuthentication(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	var allChain *listener.FilterChain
	for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
		if slices.Contains(chain.GetFilterChainMatch().GetServerNames(), "all.gateway.test") {
			allChain = chain
			break
		}
	}
	if allChain == nil {
		t.Fatal("all_of TLS filter chain is missing")
	}
	manager := decodeHTTPManager(t, allChain)

	names := httpFilterNames(manager)
	index := func(name string) int { return slices.Index(names, name) }
	if index(authenticationFilterName) < 0 ||
		index(mtlsPendingCleanupFilterName) <= index(authenticationFilterName) ||
		index(mtlsSANCardinalityFilterName) <= index(mtlsPendingCleanupFilterName) ||
		index(mtlsSharedAttributesFilterName) <= index(mtlsSANCardinalityFilterName) {
		t.Fatalf("mTLS filter order = %v", names)
	}

	var allHost *route.VirtualHost
	for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
		if host.GetName() == "all.gateway.test" {
			allHost = host
			break
		}
	}
	if allHost == nil {
		t.Fatal("all_of virtual host is missing")
	}
	var authentication httpRBAC.RBACPerRoute
	authenticationConfig := allHost.GetTypedPerFilterConfig()[authenticationFilterName]
	if authenticationConfig == nil {
		t.Fatal("all_of authentication rules are missing")
	}
	if err := authenticationConfig.UnmarshalTo(&authentication); err != nil {
		t.Fatal(err)
	}
	if policy := authentication.GetRbac().GetRules().GetPolicies()["authenticated"]; policy == nil || policy.GetCondition() != nil {
		t.Fatalf("all_of authentication still checks shared attributes: %#v", policy)
	}

	var sharedAttributes httpRBAC.RBACPerRoute
	sharedAttributesConfig := allHost.GetTypedPerFilterConfig()[mtlsSharedAttributesFilterName]
	if sharedAttributesConfig == nil {
		t.Fatal("all_of shared-attribute rules are missing")
	}
	if err := sharedAttributesConfig.UnmarshalTo(&sharedAttributes); err != nil {
		t.Fatal(err)
	}
	policy := sharedAttributes.GetRbac().GetRules().GetPolicies()["shared-attributes"]
	if policy == nil || policy.GetCondition() == nil || len(policy.GetPrincipals()) == 0 {
		t.Fatalf("all_of shared-attribute policy = %#v", policy)
	}
}
