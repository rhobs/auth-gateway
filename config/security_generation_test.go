package config

import (
	"slices"
	"strings"
	"testing"

	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

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

				if got := hasHTTPFilter(manager, jwtAuthnFilterName); got != authentication.hasJWT {
					t.Errorf("JWT filter present = %t, want %t", got, authentication.hasJWT)
				}
				if got := hasHTTPFilter(manager, apiKeyFilterName); got != authentication.hasAPIKey {
					t.Errorf("API-key filter present = %t, want %t", got, authentication.hasAPIKey)
				}
				if got := host.TypedPerFilterConfig[jwtAuthnFilterName] != nil; got != authentication.hasJWT {
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
					filter := generatedHTTPFilter(manager, jwtAuthnFilterName)
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

func newSecuritySelectorConfig(authenticatorNames []string, authAnyOf bool, policyNames []string, policyAnyOf bool) Config {
	authenticators := map[string]Authenticator{
		"issuer-one": {
			Name: "issuer-one",
			JWT: &JWTAuthenticator{
				Issuer: "https://issuer-one.jwt.test",
				JWKS:   JWKSConfig{URI: "https://jwks.jwt.test/issuer-one"},
			},
			Attributes: map[string]AttributeSource{"tenant_id": {ClaimPath: []string{"organization", "id"}}},
		},
		"issuer-two": {
			Name: "issuer-two",
			JWT: &JWTAuthenticator{
				Issuer: "https://issuer-two.jwt.test",
				JWKS:   JWKSConfig{URI: "https://jwks.jwt.test/issuer-two"},
			},
			Attributes: map[string]AttributeSource{"tenant_id": {ClaimPath: []string{"organization", "id"}}},
		},
		"partner-key": {
			Name:   "partner-key",
			APIKey: &APIKeyAuthenticator{Header: "X-Partner-Key"},
			Attributes: map[string]AttributeSource{
				"tenant_id": {Credential: new(true)},
			},
		},
	}

	config := Config{
		Version: 1,
		APIs: []API{{
			Name:     "ingest",
			Upstream: Upstream{Address: "httpbin.example.test", Port: 8080},
			Routes:   []Route{{Methods: []string{"POST"}, Path: PathMatch{Exact: "/ingest"}}},
		}},
		Servers: []Server{{
			Hostname: "gateway.example.test",
			APIs:     []string{"ingest"},
		}},
	}
	for _, name := range authenticatorNames {
		config.Authenticators = append(config.Authenticators, authenticators[name])
	}
	selection := &Authentication{}
	if authAnyOf {
		selection.AnyOf = slices.Clone(authenticatorNames)
	} else {
		selection.AllOf = slices.Clone(authenticatorNames)
	}
	config.Servers[0].Authentication = selection

	if len(policyNames) == 0 {
		return config
	}
	authorization := &Authorization{}
	if policyAnyOf {
		authorization.AnyOf = slices.Clone(policyNames)
	} else {
		authorization.AllOf = slices.Clone(policyNames)
	}
	config.Servers[0].Authorization = authorization
	for _, policyName := range policyNames {
		policy := AuthorizationPolicy{Name: policyName}
		for _, authenticatorName := range authenticatorNames {
			policy.Grants = append(policy.Grants, AuthorizationGrant{
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
