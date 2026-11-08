package gateway

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestAuthValidationFixtureContainsExpectedConfiguration(t *testing.T) {
	c := loadAuthValidationFixture(t)
	if len(c.Authenticators) != 3 || len(c.AuthorizationPolicies) != 3 {
		t.Fatalf("fixture counts = %d authenticators, %d policies", len(c.Authenticators), len(c.AuthorizationPolicies))
	}
	if got, want := c.Authenticators[0].Attributes["tenant_id"].ClaimPath, []string{"organization", "id"}; !slices.Equal(got, want) {
		t.Fatalf("tenant claim path = %v, want %v", got, want)
	}
	if source := c.Authenticators[0].Attributes["requested_tenant"]; source.Header == nil || *source.Header != "X-Tenant" {
		t.Fatalf("JWT header attribute = %#v", source)
	}
	if got, want := c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"], []string{"client-123", "client-456"}; !slices.Equal(got, want) {
		t.Fatalf("authorization values = %v, want original claim values %v", got, want)
	}
	if key := c.Authenticators[2].APIKey; key == nil || key.Secret != "auth-gateway-api-keys" || key.Header != "X-Partner-Key" ||
		!slices.Equal(credentialAttributeNamesAuthenticator(c.Authenticators[2]), []string{"tenant_id", "writer_id"}) {
		t.Fatalf("fixture API-key authenticator = %#v", key)
	}
	if source := c.Authenticators[2].Attributes["requested_tenant"]; source.Header == nil || *source.Header != "X-Tenant" {
		t.Fatalf("API-key header attribute = %#v", source)
	}
	headers := c.APIs[0].Routes[0].Processing.RequestHeaders
	if len(headers) != 2 || headers[0].Name != "X-Scope-OrgID" || headers[1].Name != "X-Writer-ID" {
		t.Fatalf("request header mappings = %#v", headers)
	}
}

func TestValidateAcceptsLiteralClaimKeysAndSingleJWTAllOf(t *testing.T) {
	config := loadAuthValidationFixture(t)
	config.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{
		ClaimPath: []string{"organization", "customer.id"},
	}
	config.Servers[0].Authentication = &gatewayapi.Authentication{AllOf: []string{"internal-jwt"}}
	config.Servers[0].Authorization = &gatewayapi.Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	if err := Validate(config); err != nil {
		t.Fatalf("Validate rejected a literal claim key and valid all_of combinations: %v", err)
	}
}

func TestLoadAcceptsMTLSAuthenticatorSchema(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	authenticator := c.Authenticators[1]
	if authenticator.MTLS == nil || authenticator.MTLS.TrustedCA == nil || authenticator.MTLS.TrustedCA.ConfigMap == nil ||
		authenticator.MTLS.TrustedCA.ConfigMap.Name != "gateway-client-ca" || authenticator.Attributes["tenant_id"].URISAN == nil ||
		authenticator.Attributes["dns_id"].DNSSAN == nil {
		t.Fatalf("loaded mTLS authenticator = %#v", authenticator)
	}
	if len(c.AuthorizationPolicies[3].Grants[0].Attributes) != 0 {
		t.Fatalf("CA-only grant has unexpected attribute constraints: %#v", c.AuthorizationPolicies[3].Grants[0])
	}
}

func TestValidateAcceptsHeaderOnlyGrant(t *testing.T) {
	c := loadAuthValidationFixture(t)
	c.AuthorizationPolicies[0].Grants[0].Attributes = map[string][]string{"requested_tenant": {"client-123"}}
	c.AuthorizationPolicies[2].Grants[0].Attributes = map[string][]string{"requested_tenant": {"client-123"}}
	if err := Validate(c); err != nil {
		t.Fatalf("header-only grants were rejected: %v", err)
	}
}

func TestValidateRejectsInvalidAuthenticationAndAuthorization(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "duplicate authenticator", want: "duplicate authenticator name", edit: func(c *gatewayapi.Config) { c.Authenticators[1].Name = c.Authenticators[0].Name }},
		{name: "missing authenticator type", want: "authenticators[0] must set exactly one of jwt, api_key, or mtls", edit: func(c *gatewayapi.Config) { c.Authenticators[0].JWT = nil }},
		{name: "missing issuer", want: "authenticators[0].jwt.issuer", edit: func(c *gatewayapi.Config) { c.Authenticators[0].JWT.Issuer = "" }},
		{name: "non-HTTPS JWKS", want: "authenticators[0].jwt.jwks.uri", edit: func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.URI = "http://sso.example.com/jwks" }},
		{name: "unsupported JWKS DNS lookup family", want: "authenticators[0].jwt.jwks.dns_lookup_family", edit: func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.DNSLookupFamily = "V5_ONLY" }},
		{name: "JWKS user information", want: "authenticators[0].jwt.jwks.uri", edit: func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.URI = "https://user@sso.example.com/jwks" }},
		{name: "duplicate audience", want: "authenticators[0].jwt.audiences", edit: func(c *gatewayapi.Config) { c.Authenticators[0].JWT.Audiences = []string{"same", "same"} }},
		{name: "empty claim path", want: "authenticators[0].attributes.tenant_id.claim_path", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{ClaimPath: []string{""}}
		}},
		{name: "duplicate policy", want: "duplicate authorization policy name", edit: func(c *gatewayapi.Config) { c.AuthorizationPolicies[1].Name = c.AuthorizationPolicies[0].Name }},
		{name: "unknown authentication method", want: "servers[0].authentication.any_of", edit: func(c *gatewayapi.Config) { c.Servers[0].Authentication.AnyOf = []string{"missing"} }},
		{name: "duplicate authentication method", want: "servers[0].authentication.any_of", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authentication.AnyOf = []string{"internal-jwt", "internal-jwt"}
		}},
		{name: "no authentication combination", want: "servers[0].authentication must set exactly one", edit: func(c *gatewayapi.Config) { c.Servers[0].Authentication = &gatewayapi.Authentication{} }},
		{name: "both authentication combinations", want: "servers[0].authentication must set exactly one", edit: func(c *gatewayapi.Config) { c.Servers[0].Authentication.AllOf = []string{"internal-jwt"} }},
		{name: "empty authentication combination", want: "servers[0].authentication.any_of", edit: func(c *gatewayapi.Config) { c.Servers[0].Authentication.AnyOf = []string{} }},
		{name: "multiple JWT methods in all_of", want: "servers[0].authentication.all_of", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authentication = &gatewayapi.Authentication{AllOf: []string{"internal-jwt", "external-jwt"}}
		}},
		{name: "unknown authorization policy", want: "servers[0].authorization.any_of", edit: func(c *gatewayapi.Config) { c.Servers[0].Authorization.AnyOf = []string{"missing"} }},
		{name: "no authorization combination", want: "servers[0].authorization must set exactly one", edit: func(c *gatewayapi.Config) { c.Servers[0].Authorization = &gatewayapi.Authorization{} }},
		{name: "both authorization combinations", want: "servers[0].authorization must set exactly one", edit: func(c *gatewayapi.Config) { c.Servers[0].Authorization.AllOf = []string{"metrics-writers"} }},
		{name: "duplicate any_of authorization policy", want: "servers[0].authorization.any_of", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authorization.AnyOf = []string{"metrics-writers", "metrics-writers"}
		}},
		{name: "duplicate all_of authorization policy", want: "servers[0].authorization.all_of", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authorization = &gatewayapi.Authorization{AllOf: []string{"metrics-writers", "metrics-writers"}}
		}},
		{name: "authorization without authentication", want: "servers[0].authorization requires authentication", edit: func(c *gatewayapi.Config) { c.Servers[0].Authentication = nil }},
		{name: "unknown grant authenticator", want: "authorization_policies[0].grants[0].authenticator", edit: func(c *gatewayapi.Config) { c.AuthorizationPolicies[0].Grants[0].Authenticator = "missing" }},
		{name: "empty grant APIs", want: "authorization_policies[0].grants[0].apis", edit: func(c *gatewayapi.Config) { c.AuthorizationPolicies[0].Grants[0].APIs = nil }},
		{name: "unknown grant API", want: "authorization_policies[0].grants[0].apis", edit: func(c *gatewayapi.Config) { c.AuthorizationPolicies[0].Grants[0].APIs = []string{"missing"} }},
		{name: "empty grant attribute values", want: "authorization_policies[0].grants[0].attributes.tenant_id", edit: func(c *gatewayapi.Config) { c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"] = nil }},
		{name: "grant attribute absent from authenticator", want: "authorization_policies[0].grants[0].attributes references", edit: func(c *gatewayapi.Config) {
			c.AuthorizationPolicies[0].Grants[0].Attributes["missing"] = []string{"value"}
		}},
		{name: "authorization policy combination empty", want: "servers[0].authorization.any_of", edit: func(c *gatewayapi.Config) { c.Servers[0].Authorization.AnyOf = []string{} }},
		{name: "invalid header field name", want: "apis[0].routes[0].processing.request_headers[0].name", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "Bad Header" }},
		{name: "reserved credential header", want: "apis[0].routes[0].processing.request_headers[0].name", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "Authorization" }},
		{name: "duplicate header field name", want: "apis[0].routes[0].processing.request_headers[1].name", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[1].Name = "x-scope-orgid" }},
		{name: "empty processing source", want: "apis[0].routes[0].processing.request_headers[0].from_attribute", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[0].FromAttribute = "" }},
		{name: "processing on public server", want: "servers[0] processing on API", edit: func(c *gatewayapi.Config) { c.Servers[0].Authentication = nil; c.Servers[0].Authorization = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadAuthValidationFixture(t)
			test.edit(&config)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAnyOfMayOmitUnusedHeaderAttributes(t *testing.T) {
	config := loadAuthValidationFixture(t)
	delete(config.Authenticators[1].Attributes, "writer_id")
	if err := Validate(config); err != nil {
		t.Fatalf("Validate rejected an any_of authenticator that omits a route attribute: %v", err)
	}

	delete(config.Authenticators[0].Attributes, "writer_id")
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "does not provide processing attribute") {
		t.Fatalf("Validate error = %v, want missing bound attribute error", err)
	}
}

func TestDuplicateJWTIssuersAreRejectedPerServer(t *testing.T) {
	config := loadAuthValidationFixture(t)
	config.Authenticators[1].JWT.Issuer = config.Authenticators[0].JWT.Issuer
	config.Authenticators[1].JWT.Audiences = []string{"another-audience"}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "same issuer") {
		t.Fatalf("Validate error = %v, want duplicate issuer binding error", err)
	}

	config = loadAuthValidationFixture(t)
	config.Authenticators[1].JWT.Issuer = config.Authenticators[0].JWT.Issuer
	config.Servers = config.Servers[:2]
	config.Servers[0].Authentication = &gatewayapi.Authentication{AnyOf: []string{"internal-jwt"}}
	config.Servers[1].Authentication = &gatewayapi.Authentication{AnyOf: []string{"external-jwt"}}
	if err := Validate(config); err != nil {
		t.Fatalf("same issuer on separate servers was rejected: %v", err)
	}
}

func TestValidateMTLSRequiresExplicitClientCA(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "missing CA", want: "authenticators[1].mtls.trusted_ca", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].MTLS.TrustedCA = nil
		}},
		{name: "empty CA", want: "authenticators[1].mtls.trusted_ca", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].MTLS.TrustedCA = &gatewayapi.TrustedCA{}
		}},
		{name: "both CA sources", want: "authenticators[1].mtls.trusted_ca", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].MTLS.TrustedCA.Filename = "/etc/client-ca.crt"
		}},
		{name: "relative CA file", want: "authenticators[1].mtls.trusted_ca.filename", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].MTLS.TrustedCA = &gatewayapi.TrustedCA{Filename: "client-ca.crt"}
		}},
		{name: "ConfigMap without Kubernetes", want: "authenticators[1].mtls.trusted_ca.config_map", edit: func(c *gatewayapi.Config) {
			c.Kubernetes = nil
		}},
		{name: "invalid ConfigMap key", want: "authenticators[1].mtls.trusted_ca.config_map.key", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].MTLS.TrustedCA.ConfigMap.Key = "../ca.crt"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "mtls-auth")
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
	c := loadConfigCase(t, "mtls-auth")
	c.Kubernetes = nil
	c.Authenticators[1].MTLS.TrustedCA = &gatewayapi.TrustedCA{Filename: "/etc/client-ca.crt"}
	if err := Validate(c); err != nil {
		t.Fatalf("file-based mTLS CA was rejected: %v", err)
	}
}

func TestValidateMTLSRequiresHTTPSAndOneAuthenticatorPerServer(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	c.Servers[0].TLSConfig = nil
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "servers[0].authentication requires tls_config") {
		t.Fatalf("HTTP mTLS binding error = %v", err)
	}

	c = loadConfigCase(t, "mtls-auth")
	second := cloneAuthenticator(c.Authenticators[1])
	second.Name = "second-client-cert"
	c.Authenticators = append(c.Authenticators, second)
	c.Servers[0].Authentication.AnyOf = []string{"client-cert", second.Name}
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "servers[0].authentication cannot contain more than one mTLS") {
		t.Fatalf("duplicate mTLS binding error = %v", err)
	}
}

func TestValidateMTLSGrantMayUseOnlyHeaders(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	c.AuthorizationPolicies[1].Grants[0].Attributes = map[string][]string{"requested_tenant": {"client-a"}}
	if err := Validate(c); err != nil {
		t.Fatalf("header-only mTLS grant was rejected: %v", err)
	}
}

func TestAPIKeyRawAuthorizationAndSharedAttributeEquality(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	keyOnly := testServerAuthenticationRules(t, c, 1).Policies["authenticated"].Principals[0]
	if matcher := keyOnly.GetSourcedMetadata().GetMetadataMatcher(); matcher == nil || matcher.Filter != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(matcher.GetPath()), []string{"identity"}) ||
		matcher.GetValue().GetStringMatch().GetExact() != "verified" {
		t.Fatalf("key-only authentication principal = %#v", keyOnly)
	}
	mixed := testServerAuthenticationRules(t, c, 2).Policies["authenticated"].Principals[0].GetOrIds().GetIds()
	if len(mixed) != 2 || mixed[0].GetSourcedMetadata() == nil || mixed[1].GetHeader().GetName() != jwtVerifiedHeaderName("issuer-one") {
		t.Fatalf("mixed any_of authentication principal = %#v", mixed)
	}
	dualPolicy := testServerAuthenticationRules(t, c, 3).Policies["authenticated"]
	principals := dualPolicy.Principals[0].GetAndIds().GetIds()
	if len(principals) != 5 || dualPolicy.Condition.GetCallExpr().GetFunction() != "_&&_" {
		t.Fatalf("all_of authentication policy = %#v", dualPolicy)
	}
	for _, equality := range dualPolicy.Condition.GetCallExpr().GetArgs() {
		if equality.GetCallExpr().GetFunction() != "_==_" {
			t.Fatalf("shared attribute condition is not exact equality: %#v", equality)
		}
	}
	for _, principal := range principals[1:] {
		value := principal.GetSourcedMetadata().GetMetadataMatcher().GetValue()
		if value.GetStringMatch().GetSafeRegex().GetRegex() != headerValuePattern {
			t.Fatalf("shared attribute was not restricted to a nonempty scalar: %#v", principal)
		}
	}
	grant := toGrantPrincipal(resolveTestConfig(t, c), c.AuthorizationPolicies[1].Grants[0])
	parts := grant.GetAndIds().GetIds()
	if len(parts) != 2 || parts[1].GetSourcedMetadata().GetMetadataMatcher().GetFilter() != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(parts[1].GetSourcedMetadata().GetMetadataMatcher().GetPath()), []string{"attribute.tenant_id"}) {
		t.Fatalf("API-key grant reads unprocessed Secret attributes: %#v", grant)
	}
	c.Servers[1].Authorization.AnyOf = []string{"jwt-writers", "key-writers"}
	effective := resolveTestConfig(t, c)
	grants := toServerRBACRules(effective, effective.servers[1]).Policies["api-ingest"].Principals[0].GetOrIds().GetIds()
	if len(grants) != 1 || grants[0].GetAndIds() == nil {
		t.Fatalf("key-only host used an unselected JWT grant: %#v", grants)
	}
}

func TestMixedAllOfComparesHeaderAndVerifiedAttributeSources(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[0].Attributes["writer_id"] = gatewayapi.AttributeSource{Header: new("X-Writer")}
	c.Authenticators[1].Attributes["tenant_id"] = gatewayapi.AttributeSource{Header: new("X-Tenant")}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	policy := testServerAuthenticationRules(t, c, 3).Policies["authenticated"]
	if len(policy.Principals[0].GetAndIds().GetIds()) != 5 {
		t.Fatalf("all_of shared-attribute principals = %#v", policy.Principals)
	}
	conjunction := policy.Condition.GetCallExpr()
	if conjunction.GetFunction() != "_&&_" || len(conjunction.GetArgs()) != 2 {
		t.Fatalf("all_of equality condition = %#v", policy.Condition)
	}
	for index, want := range [][][]string{
		{{"metadata", "filter_metadata", "envoy.filters.http.jwt_authn", "issuer-one", "organization", "id"}, {"metadata", "filter_metadata", "auth_gateway.request_headers", "x-tenant"}},
		{{"metadata", "filter_metadata", "auth_gateway.request_headers", "x-writer"}, {"metadata", "filter_metadata", "auth_gateway.api_key", "attribute.writer_id"}},
	} {
		equality := conjunction.GetArgs()[index].GetCallExpr()
		if equality.GetFunction() != "_==_" || len(equality.GetArgs()) != 2 ||
			!slices.Equal(metadataReference(equality.GetArgs()[0]), want[0]) ||
			!slices.Equal(metadataReference(equality.GetArgs()[1]), want[1]) {
			t.Fatalf("shared attribute %d compares %v, want %v", index, equality, want)
		}
	}
}

func TestRequiredHeaderRBACRulesRejectsEmptyMappings(t *testing.T) {
	_, err := requiredHeaderRBACRules(nil)
	if err == nil || !strings.Contains(err.Error(), "at least one request header mapping") {
		t.Fatalf("required header rules error = %v, want empty mapping error", err)
	}
}

func TestJWTHeaderOnlyGrantRequiresNamedVerifiedIssuer(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("X-Tenant")}
	c.AuthorizationPolicies[0].Grants[0].Attributes = map[string][]string{"requested_tenant": {"customer-a"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	if slices.Index(names, "envoy.filters.http.header_to_metadata") < 0 ||
		slices.Index(names, "envoy.filters.http.set_filter_state") >= 0 {
		t.Fatalf("header-only grant needs capture but no working attributes: %v", names)
	}
	grant := toGrantPrincipal(resolveTestConfig(t, c), c.AuthorizationPolicies[0].Grants[0]).GetAndIds().GetIds()
	if len(grant) != 2 {
		t.Fatalf("header-only JWT grant principals = %#v", grant)
	}
	header := grant[0].GetSourcedMetadata().GetMetadataMatcher()
	issuer := grant[1].GetSourcedMetadata().GetMetadataMatcher()
	if header.GetFilter() != "auth_gateway.request_headers" ||
		!slices.Equal(metadataMatcherPath(header.GetPath()), []string{"x-tenant"}) ||
		header.GetValue().GetStringMatch().GetExact() != "customer-a" ||
		issuer.GetFilter() != "envoy.filters.http.jwt_authn" ||
		!slices.Equal(metadataMatcherPath(issuer.GetPath()), []string{"issuer-one", "iss"}) ||
		issuer.GetValue().GetStringMatch().GetExact() != "https://issuer-one.jwt.test" {
		t.Fatalf("header-only JWT grant does not bind the named issuer: %#v", grant)
	}
}

func TestJWTAuthorizationReadsOriginalClaimsFromNamedProvider(t *testing.T) {
	c := resolveTestConfig(t, loadConfigCase(t, "jwt-auth-multiple-issuers"))
	rules := toServerRBACRules(c, c.servers[0])
	policy := rules.Policies["api-metrics"]
	if policy == nil || len(policy.Principals) != 1 {
		t.Fatalf("API authorization policy = %#v", policy)
	}
	grants := policy.Principals[0].GetOrIds().Ids
	if len(grants) != 2 {
		t.Fatalf("provider grant count = %d, want one for each issuer", len(grants))
	}
	gotValues := make(map[string]string, len(grants))
	for _, grant := range grants {
		claim := grant.GetSourcedMetadata()
		if claim == nil || claim.MetadataSource != rbac.MetadataSource_DYNAMIC || claim.GetMetadataMatcher().GetFilter() != "envoy.filters.http.jwt_authn" {
			t.Fatalf("grant does not use verified JWT metadata: %#v", grant)
		}
		var path []string
		for _, segment := range claim.GetMetadataMatcher().GetPath() {
			path = append(path, segment.GetKey())
		}
		if len(path) != 3 || path[1] != "organization" || path[2] != "id" {
			t.Fatalf("grant claim path = %v, want provider.organization.id", path)
		}
		valueMatcher := claim.GetMetadataMatcher().GetValue()
		branches := valueMatcher.GetOrMatch().GetValueMatchers()
		if len(branches) != 2 || branches[0].GetStringMatch() == nil || branches[1].GetListMatch() == nil {
			t.Fatalf("claim matcher = %#v, want scalar and list branches", valueMatcher)
		}
		listValueMatcher := branches[1].GetListMatch().GetOneOf()
		if listValueMatcher == nil || listValueMatcher.GetStringMatch() == nil {
			t.Fatalf("list matcher = %#v, want an exact string member matcher", branches[1].GetListMatch())
		}
		value := branches[0].GetStringMatch().GetExact()
		if listValueMatcher.GetStringMatch().GetExact() != value {
			t.Fatalf("scalar and list match values = %q and %q", value, listValueMatcher.GetStringMatch().GetExact())
		}
		gotValues[path[0]] = value
	}
	if !reflect.DeepEqual(gotValues, map[string]string{"issuer-one": "customer-a", "issuer-two": "customer-b"}) {
		t.Fatalf("raw provider grants = %v", gotValues)
	}

	config, err := toJWTFilterConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	any := config.RequirementMap[serverJWTRequirementName(0)].GetRequiresAny().Requirements
	if len(any) != 2 || any[0].GetProviderName() != "issuer-one" || any[1].GetProviderName() != "issuer-two" {
		t.Fatalf("alternative issuer requirement = %#v", any)
	}
}

func TestJWTAuthorizationMatchesAnyAllowedListClaimValue(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth")
	c.Authenticators[0].Attributes["my_list"] = gatewayapi.AttributeSource{ClaimPath: []string{"x", "my_list"}}
	grant := c.AuthorizationPolicies[0].Grants[0]
	grant.Attributes = map[string][]string{"my_list": {"y", "z"}}

	principal := toGrantPrincipal(resolveTestConfig(t, c), grant)
	claim := principal.GetSourcedMetadata()
	if claim == nil {
		t.Fatalf("grant principal = %#v, want a JWT metadata matcher", principal)
	}
	var gotPath []string
	for _, segment := range claim.GetMetadataMatcher().GetPath() {
		gotPath = append(gotPath, segment.GetKey())
	}
	if !slices.Equal(gotPath, []string{"internal-jwt", "x", "my_list"}) {
		t.Fatalf("claim path = %v, want internal-jwt.x.my_list", gotPath)
	}

	valueMatcher := claim.GetMetadataMatcher().GetValue()
	branches := valueMatcher.GetOrMatch().GetValueMatchers()
	if len(branches) != 2 || branches[0].GetOrMatch() == nil || branches[1].GetListMatch() == nil {
		t.Fatalf("claim matcher = %#v, want scalar allowlist and list-member branches", valueMatcher)
	}
	scalarValues := branches[0].GetOrMatch().GetValueMatchers()
	listMatcher := branches[1].GetListMatch().GetOneOf()
	if listMatcher == nil || listMatcher.GetOrMatch() == nil {
		t.Fatalf("list matcher = %#v, want an allowlist matcher for list members", branches[1].GetListMatch())
	}
	listValues := listMatcher.GetOrMatch().GetValueMatchers()
	if len(scalarValues) != 2 || len(listValues) != 2 {
		t.Fatalf("scalar/list allowlist lengths = %d/%d, want 2/2", len(scalarValues), len(listValues))
	}
	for i, want := range []string{"y", "z"} {
		if scalarValues[i].GetStringMatch() == nil || scalarValues[i].GetStringMatch().GetExact() != want {
			t.Fatalf("scalar allowlist value %d = %#v, want %q", i, scalarValues[i], want)
		}
		if listValues[i].GetStringMatch() == nil || listValues[i].GetStringMatch().GetExact() != want {
			t.Fatalf("list-member allowlist value %d = %#v, want %q", i, listValues[i], want)
		}
	}
}

func TestJWTAuthorizationPolicyCombinationsAreAPIScoped(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	effective := resolveTestConfig(t, c)
	rules := toServerRBACRules(effective, effective.servers[0])
	if rules.Policies["api-metrics-write"] == nil || rules.Policies["api-logs"] == nil {
		t.Fatalf("any_of policies did not generate both granted API rules: %#v", rules.Policies)
	}
	metricsGrants := rules.Policies["api-metrics-write"].Principals[0].GetOrIds().Ids
	if len(metricsGrants) != 2 {
		t.Fatalf("metrics API grant principals = %d, want one grant from each issuer", len(metricsGrants))
	}

	c.Servers[0].Authorization = &gatewayapi.Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	effective = resolveTestConfig(t, c)
	rules = toServerRBACRules(effective, effective.servers[0])
	if rules.Policies["api-metrics-write"] != nil || rules.Policies["api-logs"] != nil {
		t.Fatalf("all_of policies for disjoint APIs granted access: %#v", rules.Policies)
	}
	if rules.Policies["local-responses"] == nil {
		t.Fatal("all_of denied APIs but removed local 404/405 responses")
	}
}
