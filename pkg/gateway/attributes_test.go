package gateway

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"

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
