package gateway

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestValidateAuthenticatorAttributeSources(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "JWT missing source", want: "authenticators[0].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{}
		}},
		{name: "JWT multiple sources", want: "authenticators[0].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{ClaimPath: []string{"sub"}, Header: new("X-Tenant")}
		}},
		{name: "JWT credential source", want: "authenticators[0].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{Credential: new(true)}
		}},
		{name: "empty header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("")}
		}},
		{name: "invalid header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("Bad Header")}
		}},
		{name: "reserved header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("Authorization")}
		}},
		{name: "internal header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("X-Auth-Gateway-Identity")}
		}},
		{name: "underscore header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("X_Tenant")}
		}},
		{name: "key credential header", want: "authenticators[0].attributes.requested_tenant.header is reserved", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("x-partner-key")}
		}},
		{name: "key missing source", want: "authenticators[2].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[2].Attributes["tenant_id"] = gatewayapi.AttributeSource{}
		}},
		{name: "key false credential", want: "authenticators[2].attributes.tenant_id.credential", edit: func(c *gatewayapi.Config) {
			c.Authenticators[2].Attributes["tenant_id"] = gatewayapi.AttributeSource{Credential: new(false)}
		}},
		{name: "key claim source", want: "authenticators[2].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[2].Attributes["tenant_id"] = gatewayapi.AttributeSource{ClaimPath: []string{"sub"}}
		}},
		{name: "key multiple sources", want: "authenticators[2].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[2].Attributes["tenant_id"] = gatewayapi.AttributeSource{Credential: new(true), Header: new("X-Tenant")}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadAuthValidationFixture(t)
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateMTLSAttributeSources(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "missing source", want: "authenticators[1].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].Attributes["tenant_id"] = gatewayapi.AttributeSource{}
		}},
		{name: "false URI SAN", want: "authenticators[1].attributes.tenant_id.uri_san", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].Attributes["tenant_id"] = gatewayapi.AttributeSource{URISAN: new(false)}
		}},
		{name: "false DNS SAN", want: "authenticators[1].attributes.dns_id.dns_san", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].Attributes["dns_id"] = gatewayapi.AttributeSource{DNSSAN: new(false)}
		}},
		{name: "multiple sources", want: "authenticators[1].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].Attributes["tenant_id"] = gatewayapi.AttributeSource{URISAN: new(true), DNSSAN: new(true)}
		}},
		{name: "JWT source", want: "authenticators[1].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].Attributes["tenant_id"] = gatewayapi.AttributeSource{ClaimPath: []string{"sub"}}
		}},
		{name: "API key source", want: "authenticators[1].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[1].Attributes["tenant_id"] = gatewayapi.AttributeSource{Credential: new(true)}
		}},
		{name: "URI SAN on JWT", want: "authenticators[0].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{URISAN: new(true)}
		}},
		{name: "DNS SAN on API key", want: "authenticators[2].attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Authenticators[2].Attributes["tenant_id"] = gatewayapi.AttributeSource{DNSSAN: new(true)}
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
}

func TestHeaderMetadataCapturePreservesRequestHeader(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[1].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("x-TENANT")}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	headerFilter := slices.Index(names, "envoy.filters.http.header_to_metadata")
	if headerFilter < 0 || headerFilter <= slices.Index(names, "envoy.filters.http.api_key_auth") ||
		headerFilter >= slices.Index(names, "auth_gateway.authentication") ||
		headerFilter >= slices.Index(names, "envoy.filters.http.rbac") ||
		headerFilter >= slices.Index(names, "envoy.filters.http.header_mutation") {
		t.Fatalf("header capture is not before authentication, grants, and mutation: %v", names)
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

func TestAPIKeyAttributeFilterInitializesMissingHostConfigMap(t *testing.T) {
	c := resolveTestConfig(t, loadConfigCase(t, "api-key-auth"))
	host := &route.VirtualHost{Name: "key.gateway.test"}
	if _, err := apiKeyAttributeFilters(c, nil, []indexedVirtualHost{{serverIndex: 1, host: host}}); err != nil {
		t.Fatal(err)
	}
	if host.TypedPerFilterConfig[attributeInitializationFilterName(1)] == nil {
		t.Fatal("API-key attribute initialization was not added to the host")
	}
}

func TestAPIKeyAttributeExtractionPreservesCredentialValues(t *testing.T) {
	authenticator := gatewayapi.Authenticator{
		Name: "partner-key", APIKey: &gatewayapi.APIKeyAuthenticator{},
		Attributes: map[string]gatewayapi.AttributeSource{
			"a":                     {Credential: new(true)},
			"attribute0":            {Credential: new(true)},
			"attribute00":           {Credential: new(true)},
			"hyphen-name":           {Credential: new(true)},
			"missing":               {Credential: new(true)},
			"under_score":           {Credential: new(true)},
			strings.Repeat("z", 64): {Credential: new(true)},
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

func TestJWTAttributesUseStaticFilterConfiguration(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var attributeFilter *hcm.HttpFilter
	for _, filter := range manager.HttpFilters {
		if filter.Name == attributeFilterName {
			attributeFilter = filter
		}
	}
	if attributeFilter == nil || attributeFilter.GetTypedConfig() == nil || attributeFilter.GetConfigDiscovery() != nil {
		t.Fatalf("attribute filter = %#v, want static configuration", attributeFilter)
	}
	var attributes setfilterstate.Config
	if err := attributeFilter.GetTypedConfig().UnmarshalTo(&attributes); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		filterStateKey("tenant_id"), filterStateKey("writer_id"),
		filterStateKey("tenant_id"), filterStateKey("writer_id"),
	}
	if len(attributes.OnRequestHeaders) != len(wantKeys) {
		t.Fatalf("attribute updates = %d, want %d", len(attributes.OnRequestHeaders), len(wantKeys))
	}
	for index, update := range attributes.OnRequestHeaders {
		if update.GetObjectKey() != wantKeys[index] || !update.SkipIfEmpty {
			t.Fatalf("attribute update %d key/skip behavior = %#v/%t", index, update.GetKey(), update.SkipIfEmpty)
		}
		format := update.GetFormatString()
		if format == nil || !format.OmitEmptyValues {
			t.Fatalf("attribute formatter = %#v", update.GetValue())
		}
		expression := format.GetTextFormatSource().GetInlineString()
		if !strings.HasPrefix(expression, "%CEL(") || !strings.HasSuffix(expression, ")%") || !strings.Contains(expression, "metadata.filter_metadata") {
			t.Fatalf("attribute expression = %q, want a verified source", expression)
		}
	}
}

func TestAPIKeyInitializersAreHostScoped(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	for _, test := range []struct {
		index int
		want  int
	}{
		{index: 1, want: 2},
		{index: 2, want: 6},
	} {
		filter := apiKeyHTTPFilter(t, manager, attributeInitializationFilterName(test.index))
		if !filter.Disabled {
			t.Fatalf("server %d initializer is not host-scoped", test.index)
		}
		var initialized setfilterstate.Config
		if err := filter.GetTypedConfig().UnmarshalTo(&initialized); err != nil {
			t.Fatal(err)
		}
		if len(initialized.OnRequestHeaders) != test.want {
			t.Fatalf("server %d initializes %d attributes, want %d", test.index, len(initialized.OnRequestHeaders), test.want)
		}
		for _, value := range initialized.OnRequestHeaders {
			format := value.GetFormatString().GetTextFormatSource()
			if !value.SkipIfEmpty || format == nil || !strings.Contains(format.GetInlineString(), "metadata.filter_metadata") {
				t.Fatalf("server %d initializer reads an unsafe source: %#v", test.index, value)
			}
		}
	}
}

func TestHeaderWorkingAttributesRequireVerifiedAuthenticator(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("X-Tenant")}
	c.Authenticators[1].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("X-Tenant")}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	filter := apiKeyHTTPFilter(t, manager, attributeInitializationFilterName(2))
	var initialization setfilterstate.Config
	if err := filter.GetTypedConfig().UnmarshalTo(&initialization); err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, value := range initialization.OnRequestHeaders {
		if value.GetObjectKey() == "auth_gateway.attributes.requested_tenant" {
			sources = append(sources, value.GetFormatString().GetTextFormatSource().GetInlineString())
		}
	}
	if len(sources) != 2 ||
		!strings.Contains(sources[0], `metadata.filter_metadata["auth_gateway.api_key"]["identity"]`) ||
		!strings.Contains(sources[1], `metadata.filter_metadata["envoy.filters.http.jwt_authn"]["issuer-one"]["iss"] == "https://issuer-one.jwt.test"`) {
		t.Fatalf("mixed any_of header initializers lack credential guards: %v", sources)
	}
}
