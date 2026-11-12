package gateway

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestValidateAuthenticatorAttributeSources(t *testing.T) {
	tests := []struct {
		name          string
		authenticator int
		source        gatewayapi.AttributeSource
		want          string
	}{
		{"empty name", 0, testClaimAttribute("", "sub"), ".name"},
		{"invalid name", 0, testClaimAttribute("Bad", "sub"), ".name"},
		{"missing source", 0, gatewayapi.AttributeSource{Name: "tenant_id"}, ".from_source"},
		{"empty claim path", 0, testClaimAttribute("tenant_id"), ".value"},
		{"empty claim key", 0, testClaimAttribute("tenant_id", ""), ".value"},
		{"claim on API key", 2, testClaimAttribute("tenant_id", "sub"), ".value"},
		{"credential on JWT", 0, testTextAttribute("tenant_id", "credential", "tenant_id"), ".value"},
		{"empty credential key", 2, testTextAttribute("tenant_id", "credential", ""), ".value"},
		{"header list", 0, gatewayapi.AttributeSource{Name: "requested_tenant", FromSource: "header", Value: gatewayapi.AttributeValue{Path: []string{"X-Tenant"}, IsPath: true}}, ".value"},
		{"invalid header", 0, testTextAttribute("requested_tenant", "header", "Bad Header"), ".value"},
		{"reserved header", 0, testTextAttribute("requested_tenant", "header", "Authorization"), ".value"},
		{"credential header", 2, testTextAttribute("requested_tenant", "header", "x-partner-key"), "reserved"},
		{"certificate on JWT", 0, testTextAttribute("tenant_id", "certificate", "uri_san"), ".value"},
		{"invalid certificate value", 1, testTextAttribute("tenant_id", "certificate", "email_san"), ".value"},
		{"empty fixed value", 0, testTextAttribute("auth_origin", "fixed", ""), ".value"},
		{"fixed path", 0, gatewayapi.AttributeSource{Name: "auth_origin", FromSource: "fixed", Value: gatewayapi.AttributeValue{Path: []string{"origin"}, IsPath: true}}, ".value"},
		{"fixed control", 0, testTextAttribute("auth_origin", "fixed", "bad\u0085value"), ".value"},
		{"fixed whitespace", 0, testTextAttribute("auth_origin", "fixed", " origin "), ".value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadAuthValidationFixture(t)
			if test.authenticator == 1 {
				c = loadConfigCase(t, "mtls-auth")
			}
			setTestAttribute(&c.Authenticators[test.authenticator], test.source)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFixedAuthenticatorAttributesValidateForAllMethods(t *testing.T) {
	for _, test := range []struct {
		name, fixture string
		index         int
	}{
		{"jwt", "jwt-auth-with-attributes", 0},
		{"api key", "api-key-auth", 1},
		{"mtls", "mtls-auth", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, test.fixture)
			setTestAttribute(&c.Authenticators[test.index], testTextAttribute("auth_origin", "fixed", "source (100%)"))
			if err := Validate(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFixedAuthenticatorAttributeGeneratedOnlyForSelectedAuthenticator(t *testing.T) {
	c := loadConfigCase(t, "ext-authz")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var checkedJWT, checkedExternal bool
	for _, generated := range manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes() {
		if !strings.Contains(generated.Name, "-access-") || strings.HasSuffix(generated.Name, "-access-denied") {
			continue
		}
		var wrapper route.FilterConfig
		if err := generated.TypedPerFilterConfig[attributeFilterName].UnmarshalTo(&wrapper); err != nil {
			t.Fatal(err)
		}
		var config setfilterstate.Config
		if err := wrapper.GetConfig().UnmarshalTo(&config); err != nil {
			t.Fatal(err)
		}
		var format string
		for _, update := range config.OnRequestHeaders {
			if update.GetObjectKey() == filterStateKey("auth_origin") {
				format = update.GetFormatString().GetTextFormatSource().GetInlineString()
			}
		}
		if strings.Contains(generated.Name, "-access-0-") {
			checkedJWT = true
			if !strings.Contains(format, `\u0025`) || !strings.Contains(format, jwtAuthnFilterName) || strings.Contains(format, "100%") {
				t.Fatalf("JWT fixed attribute format = %q", format)
			}
		} else {
			checkedExternal = true
			if format != "" {
				t.Fatalf("external access initializes authenticator attribute: %q", format)
			}
		}
	}
	if !checkedJWT || !checkedExternal {
		t.Fatalf("checked JWT=%t external=%t", checkedJWT, checkedExternal)
	}
}

func TestValidateDuplicateAuthenticatorAttributeName(t *testing.T) {
	c := loadAuthValidationFixture(t)
	c.Authenticators[0].Attributes = append(c.Authenticators[0].Attributes, testClaimAttribute("tenant_id", "other"))
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "duplicates attribute") {
		t.Fatalf("duplicate attribute error = %v", err)
	}
}

func TestAPIKeySourceUsesDeclaredCredentialKey(t *testing.T) {
	authenticator := gatewayapi.Authenticator{
		Name: "partner-key", APIKey: &gatewayapi.APIKeyAuthenticator{},
		Attributes: []gatewayapi.AttributeSource{
			testTextAttribute("tenant_id", "credential", "organization_id"),
			testTextAttribute("upstream_tenant", "credential", "organization_id"),
		},
	}
	data, err := GenerateAPIKeyECDS(authenticator, []gatewayapi.APIKeyCredential{{Key: "key", Attributes: map[string]string{"organization_id": "client-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeAPIKeySecret(t, data).Credentials[0].Client; got != "organization_id=client-a" {
		t.Fatalf("client identity = %q", got)
	}
	for _, name := range []string{"tenant_id", "upstream_tenant"} {
		namespace, path := attributeMetadataPath(authenticator, name)
		if namespace != apiKeyMetadataNamespace || !slices.Equal(path, []string{"attribute.organization_id"}) {
			t.Fatalf("metadata path for %s = %q %v", name, namespace, path)
		}
	}
}

func TestHeaderMetadataCapturePreservesRequestHeader(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	setTestAttribute(&c.Authenticators[1], testTextAttribute("requested_tenant", "header", "x-TENANT"))
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	headerFilter := slices.Index(names, "envoy.filters.http.header_to_metadata")
	if headerFilter < 0 || headerFilter <= slices.Index(names, "envoy.filters.http.api_key_auth") ||
		headerFilter >= slices.Index(names, "envoy.filters.http.rbac") ||
		headerFilter >= slices.Index(names, "envoy.filters.http.header_mutation") {
		t.Fatalf("header capture must follow credentials and precede grants and mutation: %v", names)
	}
	var metadata headertometadata.Config
	if err := manager.HttpFilters[headerFilter].GetTypedConfig().UnmarshalTo(&metadata); err != nil {
		t.Fatal(err)
	}
	var captured []*headertometadata.Config_Rule
	for _, rule := range metadata.GetRequestRules() {
		if rule.GetOnHeaderPresent().GetMetadataNamespace() == "auth_gateway.request_headers" {
			captured = append(captured, rule)
		}
	}
	if len(captured) != 1 || captured[0].Header != "x-tenant" || captured[0].Remove ||
		captured[0].OnHeaderMissing != nil || captured[0].GetOnHeaderPresent().GetKey() != "x-tenant" ||
		captured[0].GetOnHeaderPresent().GetType() != headertometadata.Config_STRING ||
		captured[0].GetOnHeaderPresent().GetEncode() != headertometadata.Config_NONE {
		t.Fatalf("header capture rules = %#v", captured)
	}
}

func TestAPIKeyAttributeExtractionPreservesCredentialValues(t *testing.T) {
	authenticator := gatewayapi.Authenticator{
		Name: "partner-key", APIKey: &gatewayapi.APIKeyAuthenticator{},
		Attributes: []gatewayapi.AttributeSource{
			testTextAttribute("a", "credential", "a"),
			testTextAttribute("attribute0", "credential", "attribute0"),
			testTextAttribute("attribute00", "credential", "attribute00"),
			testTextAttribute("hyphen-name", "credential", "hyphen-name"),
			testTextAttribute("missing", "credential", "missing"),
			testTextAttribute("under_score", "credential", "under_score"),
			testTextAttribute(strings.Repeat("z", 64), "credential", strings.Repeat("z", 64)),
		},
	}
	values := map[string]string{
		"a":                     "attribute0=not-a-binding",
		"attribute0":            `equals=percent%3B+slash/quote"backslash\`,
		"attribute00":           "prefix names stay separate",
		"hyphen-name":           `literal\1$1`,
		"under_score":           "caf\u00e9",
		strings.Repeat("z", 64): "last-value",
	}
	data, err := GenerateAPIKeyECDS(authenticator, []gatewayapi.APIKeyCredential{{Key: "key", Attributes: values}})
	if err != nil {
		t.Fatal(err)
	}
	identity := decodeAPIKeySecret(t, data).Credentials[0].Client
	filter, err := requestMetadataFilter(authenticator, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var metadata headertometadata.Config
	if err := filter.GetTypedConfig().UnmarshalTo(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, rule := range metadata.RequestRules[1:] {
		attribute := strings.TrimPrefix(rule.OnHeaderPresent.Key, "attribute.")
		rewrite := rule.OnHeaderPresent.RegexValueRewrite
		pattern, err := regexp.Compile(rewrite.Pattern.Regex)
		if err != nil {
			t.Fatal(err)
		}
		matches := pattern.FindStringSubmatch(identity)
		if len(matches) != 2 || matches[1] != values[attribute] {
			t.Errorf("attribute %s: extraction = %q, want %q", attribute, matches, values[attribute])
		}
		for _, withoutAttribute := range []string{"api-key", "other=value", "other=" + attribute + "=not-a-binding"} {
			matches := pattern.FindStringSubmatch(withoutAttribute)
			if len(matches) != 2 || matches[1] != "" {
				t.Errorf("attribute %s: extraction from %q = %q, want an empty value", attribute, withoutAttribute, matches)
			}
		}
		if rule.OnHeaderMissing != nil {
			t.Errorf("attribute %s supplies a value without a verified identity", attribute)
		}
	}
}
