package config

import (
	"strings"
	"testing"
)

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
			server := c.Servers[1]
			server.Authentication = &Authentication{AnyOf: test.selected}
			initialization := c.toServerAttributeInitializationConfig(server)
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
	c := loadConfigCase(t, "mtls-auth")
	initialization := c.toServerAttributeInitializationConfig(c.Servers[1])
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
			c := loadConfigCase(t, fixture)
			for _, server := range c.Servers {
				if server.Authentication == nil || server.Authentication.AllOf == nil {
					continue
				}
				initialization := c.toServerAttributeInitializationConfig(server)
				for _, update := range initialization.OnRequestHeaders {
					if update.GetObjectKey() == "auth_gateway.authenticator" || strings.Contains(update.GetFormatString().GetTextFormatSource().GetInlineString(), `filter_state["auth_gateway.authenticator"]`) {
						t.Fatal("all_of initialization uses a single any_of identity")
					}
				}
			}
		})
	}
}
