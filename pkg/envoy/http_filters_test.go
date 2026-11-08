package envoy

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

func TestConditionalJWTFilterOrder(t *testing.T) {
	plainJWT := []string{requestControlsFilterName, configuration.JwtAuthnFilterName, authorizationFilterName, credentialCleanupFilterName, routerFilterName}
	attributesJWT := []string{
		requestControlsFilterName, configuration.JwtAuthnFilterName, attributeFilterName, authorizationFilterName,
		requiredHeaderFilterName, credentialCleanupFilterName, headerMutationFilterName, routerFilterName,
	}
	tests := []struct {
		name                  string
		fixture               string
		wantOrder             []string
		wantFiles             []string
		withoutRequestMetrics bool
	}{
		{name: "public", fixture: "public-routing", wantOrder: []string{requestControlsFilterName, routerFilterName}, wantFiles: []string{configuration.EnvoyConfigFilename}},
		{name: "plain JWT", fixture: "jwt-auth", wantOrder: plainJWT, wantFiles: []string{configuration.EnvoyConfigFilename}},
		{name: "direct headers", fixture: "jwt-auth-with-headers", wantOrder: attributesJWT, wantFiles: []string{configuration.EnvoyConfigFilename}},
		{name: "claim attributes", fixture: "jwt-auth-with-attributes", wantOrder: attributesJWT, wantFiles: []string{configuration.EnvoyConfigFilename, "server-certificate-1.yaml"}, withoutRequestMetrics: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, test.fixture)
			if test.withoutRequestMetrics {
				for i := range c.APIs {
					c.APIs[i].Metrics = nil
				}
			}
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
			manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
			if got := httpFilterNames(manager); !slices.Equal(got, test.wantOrder) {
				t.Fatalf("HTTP filter order = %v, want %v", got, test.wantOrder)
			}
			got := make([]string, 0, len(files.All()))
			for _, file := range files.All() {
				got = append(got, filepath.Base(file.Path))
			}
			slices.Sort(got)
			if !slices.Equal(got, test.wantFiles) {
				t.Fatalf("generated files = %v, want %v", got, test.wantFiles)
			}
		})
	}
}

func TestRequestMetricsFilterPrecedesJWTAttributeInitialization(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	want := []string{
		requestControlsFilterName, requestMetricsFilterName, configuration.JwtAuthnFilterName, attributeFilterName,
		authorizationFilterName, requiredHeaderFilterName, credentialCleanupFilterName, headerMutationFilterName, routerFilterName,
	}
	if got := httpFilterNames(manager); !slices.Equal(got, want) {
		t.Fatalf("HTTP filters = %v, want %v", got, want)
	}
}

func TestRequestMetricsFilterPrecedesAPIKeyAuthentication(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	got := httpFilterNames(manager)
	want := []string{requestControlsFilterName, requestMetricsFilterName, configuration.JwtAuthnFilterName, apiKeyFilterName}
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) {
		t.Fatalf("HTTP filter prefix = %v, want %v", got, want)
	}
}

func TestMixedAnyOfSelectsIdentityBeforeInitializingAttributes(t *testing.T) {
	const jwtVerified = `"envoy.filters.http.jwt_authn" in metadata.filter_metadata && "issuer-one" in metadata.filter_metadata["envoy.filters.http.jwt_authn"] && "iss" in metadata.filter_metadata["envoy.filters.http.jwt_authn"]["issuer-one"] && type(metadata.filter_metadata["envoy.filters.http.jwt_authn"]["issuer-one"]["iss"]) == string && metadata.filter_metadata["envoy.filters.http.jwt_authn"]["issuer-one"]["iss"] == "https://issuer-one.jwt.test"`
	const certificateVerified = `"auth_gateway.mtls" in metadata.filter_metadata && "fingerprint" in metadata.filter_metadata["auth_gateway.mtls"] && type(metadata.filter_metadata["auth_gateway.mtls"]["fingerprint"]) == string && size(metadata.filter_metadata["auth_gateway.mtls"]["fingerprint"]) >= 64`
	const keyVerified = `"auth_gateway.api_key" in metadata.filter_metadata && "identity" in metadata.filter_metadata["auth_gateway.api_key"] && type(metadata.filter_metadata["auth_gateway.api_key"]["identity"]) == string && metadata.filter_metadata["auth_gateway.api_key"]["identity"] != ""`
	verified := map[string]string{"issuer-one": jwtVerified, "client-cert": certificateVerified, "partner-key": keyVerified}
	for _, test := range []struct {
		name     string
		selected []string
		want     []string
	}{
		{
			name:     "JWT before API key",
			selected: []string{"partner-key", "issuer-one"},
			want:     []string{"partner-key", "issuer-one"},
		},
		{
			name:     "JWT before certificate",
			selected: []string{"client-cert", "issuer-one"},
			want:     []string{"client-cert", "issuer-one"},
		},
		{
			name:     "certificate before API key",
			selected: []string{"partner-key", "client-cert"},
			want:     []string{"partner-key", "client-cert"},
		},
		{
			name:     "JWT before certificate before API key",
			selected: []string{"partner-key", "client-cert", "issuer-one"},
			want:     []string{"partner-key", "client-cert", "issuer-one"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "mtls-auth")
			c.Servers[1].Authentication = &gatewayapi.Authentication{AnyOf: test.selected}
			effective := resolveTestConfig(t, c)
			initialization := toServerAttributeInitializationConfig(effective, effective.ResolvedServers[1])
			if len(initialization.OnRequestHeaders) <= len(test.want) {
				t.Fatal("mixed any_of is missing identity selection or attributes")
			}
			for index, name := range test.want {
				selection := initialization.OnRequestHeaders[index]
				if got := selection.GetObjectKey(); got != "auth_gateway.authenticator" {
					t.Fatalf("key %d = %q, want identity selection before attributes", index, got)
				}
				want := "%CEL(((" + verified[name] + `) ? "` + name + `" : ""))%`
				if got := selection.GetFormatString().GetTextFormatSource().GetInlineString(); got != want || !selection.SkipIfEmpty {
					t.Fatalf("identity selection %d = %s, want %s with skip_if_empty", index, got, want)
				}
			}
		})
	}
}

func TestMixedAnyOfGuardsEveryAttributeWithSelectedIdentity(t *testing.T) {
	c := resolveTestConfig(t, loadConfigCase(t, "mtls-auth"))
	initialization := toServerAttributeInitializationConfig(c, c.ResolvedServers[1])
	want := []struct{ authenticator, attribute, source string }{
		{"partner-key", "requested_tenant", `["auth_gateway.request_headers"]["x-tenant"]`},
		{"partner-key", "tenant_id", `["auth_gateway.api_key"]["attribute.tenant_id"]`},
		{"client-cert", "dns_id", `["auth_gateway.mtls"]["dns_san"]`},
		{"client-cert", "requested_tenant", `["auth_gateway.request_headers"]["x-tenant"]`},
		{"client-cert", "tenant_id", `["auth_gateway.mtls"]["uri_san"]`},
		{"issuer-one", "requested_tenant", `["auth_gateway.request_headers"]["x-tenant"]`},
		{"issuer-one", "tenant_id", `["envoy.filters.http.jwt_authn"]["issuer-one"]["organization"]["id"]`},
	}
	if got := len(initialization.OnRequestHeaders); got != len(want)+3 {
		t.Fatalf("initialization updates = %d, want three selections and %d attribute updates", got, len(want))
	}
	for index, expected := range want {
		update := initialization.OnRequestHeaders[index+3]
		if got := update.GetObjectKey(); got != "auth_gateway.attributes."+expected.attribute {
			t.Fatalf("attribute %d = %q, want %q", index, got, expected.attribute)
		}
		expression := update.GetFormatString().GetTextFormatSource().GetInlineString()
		guard := `%CEL(("auth_gateway.authenticator" in filter_state && filter_state["auth_gateway.authenticator"] == b"` + expected.authenticator + `") ? (`
		if !strings.HasPrefix(expression, guard) || !strings.HasSuffix(expression, `) : "")%`) {
			t.Errorf("%s.%s can initialize outside its selected identity: %s", expected.authenticator, expected.attribute, expression)
		}
		if !strings.Contains(expression, expected.source) || !strings.Contains(expression, ` != ""`) || !update.SkipIfEmpty {
			t.Errorf("%s.%s does not preserve missing/empty source behavior: %s", expected.authenticator, expected.attribute, expression)
		}
	}
}

func TestAllOfKeepsAttributeSourcesSeparateFromAnyOfSelection(t *testing.T) {
	for _, fixture := range []string{"api-key-auth", "mtls-auth"} {
		t.Run(fixture, func(t *testing.T) {
			c := resolveTestConfig(t, loadConfigCase(t, fixture))
			for _, server := range c.ResolvedServers {
				if server.Authentication == nil || server.Authentication.AllOf == nil {
					continue
				}
				initialization := toServerAttributeInitializationConfig(c, server)
				for _, update := range initialization.OnRequestHeaders {
					if update.GetObjectKey() == "auth_gateway.authenticator" || strings.Contains(update.GetFormatString().GetTextFormatSource().GetInlineString(), `filter_state["auth_gateway.authenticator"]`) {
						t.Fatal("all_of initialization uses a single any_of identity")
					}
				}
			}
		})
	}
}

func TestGenerateAuthenticationAndAuthorizationSelectorCombinations(t *testing.T) {
	authenticationSelectors := []struct {
		name      string
		names     []string
		anyOf     bool
		hasJWT    bool
		hasAPIKey bool
	}{
		{name: "one JWT any_of", names: []string{"issuer-one"}, anyOf: true, hasJWT: true},
		{name: "one JWT all_of", names: []string{"issuer-one"}, hasJWT: true},
		{name: "one API key any_of", names: []string{"partner-key"}, anyOf: true, hasAPIKey: true},
		{name: "one API key all_of", names: []string{"partner-key"}, hasAPIKey: true},
		{name: "two JWTs any_of", names: []string{"issuer-one", "issuer-two"}, anyOf: true, hasJWT: true},
		{name: "JWT and key any_of", names: []string{"issuer-one", "partner-key"}, anyOf: true, hasJWT: true, hasAPIKey: true},
		{name: "JWT and key all_of", names: []string{"issuer-one", "partner-key"}, hasJWT: true, hasAPIKey: true},
		{name: "two JWTs and key any_of", names: []string{"issuer-one", "issuer-two", "partner-key"}, anyOf: true, hasJWT: true, hasAPIKey: true},
	}
	authorizationSelectors := []struct {
		name     string
		policies []string
		anyOf    bool
	}{
		{name: "no policy"},
		{name: "one policy any_of", policies: []string{"allow-ingest"}, anyOf: true},
		{name: "one policy all_of", policies: []string{"allow-ingest"}},
		{name: "multiple policies any_of", policies: []string{"allow-ingest", "allow-ingest-two"}, anyOf: true},
		{name: "multiple policies all_of", policies: []string{"allow-ingest", "allow-ingest-two"}},
	}

	const wantCells = 40
	cells := 0
	for _, authentication := range authenticationSelectors {
		for _, authorization := range authorizationSelectors {
			t.Run(authentication.name+" / "+authorization.name, func(t *testing.T) {
				cells++
				config := newSecuritySelectorConfig(authentication.names, authentication.anyOf, authorization.policies, authorization.anyOf)
				files, err := Generate(config)
				if err != nil {
					t.Fatalf("Generate() error = %v", err)
				}

				bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
				if len(bootstrap.GetStaticResources().GetListeners()) != 1 {
					t.Fatal("generated listener count is not one")
				}
				chains := bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains()
				if len(chains) != 1 {
					t.Fatalf("generated filter chain count = %d, want one HTTP chain", len(chains))
				}
				manager := decodeHTTPManager(t, chains[0])
				hosts := manager.GetRouteConfig().GetVirtualHosts()
				if len(hosts) != 1 {
					t.Fatalf("generated virtual host count = %d, want one", len(hosts))
				}
				host := hosts[0]

				if got := hasHTTPFilter(manager, configuration.JwtAuthnFilterName); got != authentication.hasJWT {
					t.Errorf("JWT filter present = %t, want %t", got, authentication.hasJWT)
				}
				if got := hasHTTPFilter(manager, apiKeyFilterName); got != authentication.hasAPIKey {
					t.Errorf("API-key filter present = %t, want %t", got, authentication.hasAPIKey)
				}
				if got := host.TypedPerFilterConfig[configuration.JwtAuthnFilterName] != nil; got != authentication.hasJWT {
					t.Errorf("per-host JWT requirement present = %t, want %t", got, authentication.hasJWT)
				}
				if got := host.TypedPerFilterConfig[apiKeyFilterName] != nil; got != authentication.hasAPIKey {
					t.Errorf("per-host API-key matcher present = %t, want %t", got, authentication.hasAPIKey)
				}
				if authentication.hasAPIKey {
					keyRoute := apiKeyPerHostMatcher(t, host)
					wantFallbackMatcher := authentication.anyOf && authentication.hasJWT
					if got := keyRoute.GetXdsMatcher() != nil; got != wantFallbackMatcher {
						t.Errorf("API-key fallback matcher present = %t, want %t", got, wantFallbackMatcher)
					}
				}
				if got := hasHTTPFilter(manager, authenticationFilterName); got != authentication.hasAPIKey {
					t.Errorf("API-key authentication RBAC filter present = %t, want %t", got, authentication.hasAPIKey)
				}

				wantJWTNames := selectedJWTNames(authentication.names)
				var gotJWKSNames []string
				for _, cluster := range bootstrap.GetStaticResources().GetClusters() {
					if strings.HasPrefix(cluster.GetName(), "jwks-") {
						gotJWKSNames = append(gotJWKSNames, strings.TrimPrefix(cluster.GetName(), "jwks-"))
					}
				}
				slices.Sort(wantJWTNames)
				slices.Sort(gotJWKSNames)
				if !slices.Equal(gotJWKSNames, wantJWTNames) {
					t.Errorf("generated JWKS providers = %v, want selected issuers %v", gotJWKSNames, wantJWTNames)
				}

				if authentication.hasJWT {
					filter := generatedHTTPFilter(manager, configuration.JwtAuthnFilterName)
					var jwtConfig jwt.JwtAuthentication
					if err := filter.GetTypedConfig().UnmarshalTo(&jwtConfig); err != nil {
						t.Fatalf("decode JWT filter: %v", err)
					}
					if len(jwtConfig.GetProviders()) != len(wantJWTNames) {
						t.Fatalf("JWT provider count = %d, want %d", len(jwtConfig.GetProviders()), len(wantJWTNames))
					}
					var gotJWTNames []string
					for name := range jwtConfig.GetProviders() {
						gotJWTNames = append(gotJWTNames, name)
					}
					slices.Sort(gotJWTNames)
					if !slices.Equal(gotJWTNames, wantJWTNames) {
						t.Fatalf("generated JWT providers = %v, want selected issuers %v", gotJWTNames, wantJWTNames)
					}
					requirement := jwtConfig.GetRequirementMap()[serverJWTRequirementName(0)]
					if requirement == nil {
						t.Fatal("server JWT requirement is missing")
					}
					switch {
					case authentication.anyOf && authentication.hasAPIKey:
						if requirement.GetAllowMissingOrFailed() == nil {
							t.Fatalf("mixed any_of JWT requirement = %v, want allow-missing-or-failed", requirement)
						}
					case len(wantJWTNames) == 1:
						if requirement.GetProviderName() != wantJWTNames[0] {
							t.Fatalf("single JWT requirement = %v, want provider %q", requirement, wantJWTNames[0])
						}
					default:
						providers := requirement.GetRequiresAny().GetRequirements()
						if len(providers) != len(wantJWTNames) {
							t.Fatalf("multiple JWT requirement = %v, want %d alternatives", requirement, len(wantJWTNames))
						}
						for index, name := range wantJWTNames {
							if providers[index].GetProviderName() != name {
								t.Fatalf("JWT requirement %d = %v, want provider %q", index, providers[index], name)
							}
						}
					}
				}

				packedRBAC := host.TypedPerFilterConfig[authorizationFilterName]
				if packedRBAC == nil {
					t.Fatal("per-host authorization rules are missing")
				}
				var authorizationConfig httpRBAC.RBACPerRoute
				if err := packedRBAC.UnmarshalTo(&authorizationConfig); err != nil {
					t.Fatalf("decode per-host authorization rules: %v", err)
				}
				policies := authorizationConfig.GetRbac().GetRules().GetPolicies()
				if policies[localResponsePolicyName] == nil {
					t.Fatal("local 404/405 responses lost their allow policy")
				}
				apiPolicy := policies["api-ingest"]
				if len(authorization.policies) == 0 {
					if apiPolicy != nil {
						t.Fatalf("unselected API policy was generated: %v", apiPolicy)
					}
					if len(policies) != 1 {
						t.Fatalf("protected server without authorization has policies %v, want only local responses", policies)
					}
					return
				}
				if apiPolicy == nil || len(apiPolicy.GetPrincipals()) != 1 {
					t.Fatalf("selected authorization policies generated API rule %v", apiPolicy)
				}
				principal := apiPolicy.GetPrincipals()[0]
				if authorization.anyOf {
					grants := principal.GetOrIds().GetIds()
					wantGrantCount := len(authorization.policies) * len(authentication.names)
					if len(grants) != wantGrantCount {
						t.Fatalf("any_of policy grant count = %d, want %d", len(grants), wantGrantCount)
					}
				} else {
					selectedPolicies := principal.GetAndIds().GetIds()
					if len(selectedPolicies) != len(authorization.policies) {
						t.Fatalf("all_of policy count = %d, want %d", len(selectedPolicies), len(authorization.policies))
					}
					for index, selectedPolicy := range selectedPolicies {
						grants := selectedPolicy.GetOrIds().GetIds()
						if len(grants) != len(authentication.names) {
							t.Fatalf("all_of policy %d grant count = %d, want %d", index, len(grants), len(authentication.names))
						}
					}
				}
			})
		}
	}
	if cells != wantCells {
		t.Fatalf("generated selector cases = %d, want %d", cells, wantCells)
	}
}

func newSecuritySelectorConfig(authenticatorNames []string, authAnyOf bool, policyNames []string, policyAnyOf bool) gatewayapi.Config {
	authenticators := map[string]gatewayapi.Authenticator{
		"issuer-one": {
			Name: "issuer-one",
			JWT: &gatewayapi.JWTAuthenticator{
				Issuer: "https://issuer-one.jwt.test",
				JWKS:   gatewayapi.JWKSConfig{URI: "https://jwks.jwt.test/issuer-one"},
			},
			Attributes: map[string]gatewayapi.AttributeSource{"tenant_id": {ClaimPath: []string{"organization", "id"}}},
		},
		"issuer-two": {
			Name: "issuer-two",
			JWT: &gatewayapi.JWTAuthenticator{
				Issuer: "https://issuer-two.jwt.test",
				JWKS:   gatewayapi.JWKSConfig{URI: "https://jwks.jwt.test/issuer-two"},
			},
			Attributes: map[string]gatewayapi.AttributeSource{"tenant_id": {ClaimPath: []string{"organization", "id"}}},
		},
		"partner-key": {
			Name:   "partner-key",
			APIKey: &gatewayapi.APIKeyAuthenticator{Header: "X-Partner-Key"},
			Attributes: map[string]gatewayapi.AttributeSource{
				"tenant_id": {Credential: new(true)},
			},
		},
	}

	config := gatewayapi.Config{
		Version: 1,
		APIs: []gatewayapi.API{{
			Name:     "ingest",
			Upstream: gatewayapi.Upstream{Address: "httpbin.example.test", Port: 8080},
			Routes:   []gatewayapi.Route{{Methods: []string{"POST"}, Path: gatewayapi.PathMatch{Exact: "/ingest"}}},
		}},
		Servers: []gatewayapi.Server{{
			Hostname: "gateway.example.test",
			APIs:     []string{"ingest"},
		}},
	}
	for _, name := range authenticatorNames {
		config.Authenticators = append(config.Authenticators, authenticators[name])
	}
	selection := &gatewayapi.Authentication{}
	if authAnyOf {
		selection.AnyOf = slices.Clone(authenticatorNames)
	} else {
		selection.AllOf = slices.Clone(authenticatorNames)
	}
	config.Servers[0].Authentication = selection

	if len(policyNames) == 0 {
		return config
	}
	authorization := &gatewayapi.Authorization{}
	if policyAnyOf {
		authorization.AnyOf = slices.Clone(policyNames)
	} else {
		authorization.AllOf = slices.Clone(policyNames)
	}
	config.Servers[0].Authorization = authorization
	for _, policyName := range policyNames {
		policy := gatewayapi.AuthorizationPolicy{Name: policyName}
		for _, authenticatorName := range authenticatorNames {
			policy.Grants = append(policy.Grants, gatewayapi.AuthorizationGrant{
				Authenticator: authenticatorName,
				APIs:          []string{"ingest"},
				Attributes:    map[string][]string{"tenant_id": {"team-a"}},
			})
		}
		config.AuthorizationPolicies = append(config.AuthorizationPolicies, policy)
	}
	return config
}

func selectedJWTNames(authenticatorNames []string) []string {
	var names []string
	for _, name := range authenticatorNames {
		if strings.HasPrefix(name, "issuer-") {
			names = append(names, name)
		}
	}
	return names
}

func hasHTTPFilter(manager *hcm.HttpConnectionManager, name string) bool {
	return generatedHTTPFilter(manager, name) != nil
}

func generatedHTTPFilter(manager *hcm.HttpConnectionManager, name string) *hcm.HttpFilter {
	for _, filter := range manager.GetHttpFilters() {
		if filter.GetName() == name {
			return filter
		}
	}
	return nil
}
