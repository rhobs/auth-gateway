//go:build envoyruntime

package gateway

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestEnvoyAPIKeyAttributeLayouts(t *testing.T) {
	certificate, key := runtimeCertificate(t)
	for _, test := range []struct {
		name             string
		count            int
		valueBytes       int
		longName         bool
		absentFromClient bool
	}{
		{name: "10-attributes", count: 10},
		{name: "20-attributes", count: 20},
		{name: "longest-attribute-name", count: 1, longName: true},
		{name: "combined-identity-over-8-KiB", count: 20, valueBytes: 512},
		{name: "maximum-attribute-value", count: 1, valueBytes: 8191},
		{name: "attribute-absent-from-client", count: 1, absentFromClient: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := apiKeyAttributesConfig(t, test.count)
			if test.longName {
				name := strings.Repeat("z", 64)
				source := *testAttribute(&c.Authenticators[0], "attribute00")
				source.Name = name
				source.Value.Text = name
				setTestAttribute(&c.Authenticators[0], source)
				removeTestAttribute(&c.Authenticators[0], "attribute00")
				c.APIs[0].Routes[0].Processing.RequestHeaders[0].FromAttribute = name
				grant := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0]
				grant.Attributes[name] = grant.Attributes["attribute00"]
				delete(grant.Attributes, "attribute00")
			}
			if test.valueBytes > 0 {
				c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes["attribute00"].Values = []string{"value00" + strings.Repeat("v", test.valueBytes-len("value00"))}
			}
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			validatePinnedEnvoyFiles(t, c, files, "", certificate, key)

			configDir := runtimeDirectory(t)
			for _, file := range files.All() {
				runtimeLiveWriteGeneratedFile(t, configDir, file)
			}
			var mappings []gatewayapi.RequestHeaderMapping
			if processing := c.APIs[0].Routes[0].Processing; processing != nil {
				mappings = processing.RequestHeaders
			}
			values := make(map[string]string, test.count)
			for index, mapping := range mappings {
				value := fmt.Sprintf("value%02d", index)
				if test.valueBytes > 0 {
					value += strings.Repeat("v", test.valueBytes-len(value))
				}
				values[mapping.FromAttribute] = value
			}
			authenticator := c.Authenticators[0]
			credential := gatewayapi.APIKeyCredential{Key: "attribute-key", Attributes: values}
			if test.absentFromClient {
				authenticator.Attributes = nil
				credential.Attributes = nil
			}
			credentials, err := GenerateAPIKeyECDS(authenticator, []gatewayapi.APIKeyCredential{credential})
			if err != nil {
				t.Fatal(err)
			}
			runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: APIKeyECDSPath, Contents: credentials})
			harness := runtimeLiveStart(t, configDir, nil)
			var response runtimeLiveResponse
			runtimeLiveAwait(t, harness, "API-key attribute extraction", time.Time{}, func() (bool, string) {
				response = harness.request(false, runtimeLiveKeyHost, "attribute-key", http.MethodPost, "/ingest", runtimeLiveBody)
				if test.absentFromClient {
					return response.err == nil && response.status == http.StatusForbidden, response.describe()
				}
				return runtimeLiveEchoMatches(response, http.StatusOK, "caller-controlled", http.MethodPost, "/anything", runtimeLiveBody), response.describe()
			})
			if test.absentFromClient {
				return
			}
			for _, mapping := range mappings {
				if got, want := runtimeLiveHeader(response.echo.Headers, mapping.Name), values[mapping.FromAttribute]; got != want {
					t.Errorf("%s = %q, want %q", mapping.Name, got, want)
				}
			}
			for _, header := range []string{"Authorization", "X-Partner-Key", "X-Auth-Gateway-API-Key-Client"} {
				if got := runtimeLiveHeader(response.echo.Headers, header); got != "" {
					t.Errorf("credential header %s leaked: %q", header, got)
				}
			}
		})
	}
}
