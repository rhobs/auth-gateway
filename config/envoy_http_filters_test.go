package config

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestConditionalJWTFilterOrder(t *testing.T) {
	plainJWT := []string{requestControlsFilterName, jwtAuthnFilterName, authorizationFilterName, credentialCleanupFilterName, routerFilterName}
	attributesJWT := []string{
		requestControlsFilterName, jwtAuthnFilterName, attributeFilterName, authorizationFilterName,
		requiredHeaderFilterName, credentialCleanupFilterName, headerMutationFilterName, routerFilterName,
	}
	tests := []struct {
		name                  string
		fixture               string
		wantOrder             []string
		wantFiles             []string
		withoutRequestMetrics bool
	}{
		{name: "public", fixture: "public-routing", wantOrder: []string{requestControlsFilterName, routerFilterName}, wantFiles: []string{envoyConfigFilename}},
		{name: "plain JWT", fixture: "jwt-auth", wantOrder: plainJWT, wantFiles: []string{envoyConfigFilename}},
		{name: "direct headers", fixture: "jwt-auth-with-headers", wantOrder: attributesJWT, wantFiles: []string{envoyConfigFilename}},
		{name: "claim attributes", fixture: "jwt-auth-with-attributes", wantOrder: attributesJWT, wantFiles: []string{envoyConfigFilename, "server-certificate-1.yaml"}, withoutRequestMetrics: true},
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
		requestControlsFilterName, requestMetricsFilterName, jwtAuthnFilterName, attributeFilterName,
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
	want := []string{requestControlsFilterName, requestMetricsFilterName, jwtAuthnFilterName, apiKeyFilterName}
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) {
		t.Fatalf("HTTP filter prefix = %v, want %v", got, want)
	}
}
