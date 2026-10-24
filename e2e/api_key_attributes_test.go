//go:build e2e

package e2e

import (
	"fmt"
	"maps"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rhobs/auth-gateway/config"
)

var apiKeyAttributesNS = e2eNamespace("auth-gateway-api-key-attributes-e2e")

var _ = Describe("API-key credential attributes", Label("gateway", "api-key", "authentication", "namespace-"+apiKeyAttributesNS), Ordered, ContinueOnFailure, func() {
	var gateway *apiKeyE2E
	var values map[string]string

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(apiKeyAttributesNS) })
		values = map[string]string{"tenant_id": "client-a", "writer_id": "writer-a"}
		for index := range 20 {
			values[fmt.Sprintf("attribute%02d", index)] = fmt.Sprintf("value%02d=part%%3B", index)
		}
		values["attribute03"] = "tenant_id=spoof%3Bwriter_id=spoof"
		values["attribute07"] = `literal\1$1+%25`
		credentials := []config.APIKeyCredential{{Key: "attribute-key", Attributes: values}}
		for _, index := range []int{0, 9, 19} {
			missing := maps.Clone(values)
			delete(missing, fmt.Sprintf("attribute%02d", index))
			credentials = append(credentials, config.APIKeyCredential{
				Key: fmt.Sprintf("missing-%02d", index), Attributes: missing,
			})
		}
		var err error
		gateway, err = setupAPIKeyGatewayWithShape(ctx, apiKeyAttributesNS, true, credentials, "attribute-key", func(c *config.Config) {
			for index := range 20 {
				name := fmt.Sprintf("attribute%02d", index)
				c.Authenticators[0].Attributes[name] = config.AttributeSource{Credential: new(true)}
				processing := c.APIs[0].Routes[0].Processing
				processing.RequestHeaders = append(processing.RequestHeaders, config.RequestHeaderMapping{
					Name: fmt.Sprintf("X-Attribute%02d", index), FromAttribute: name,
				})
			}
		})
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(8*time.Minute))

	It("forwards every bound value and removes credentials with a larger attribute layout", func(ctx SpecContext) {
		headers := http.Header{"X-Auth-Gateway-API-Key-Client": []string{"spoofed-identity"}}
		for index := range 20 {
			headers.Set(fmt.Sprintf("X-Attribute%02d", index), "caller-controlled")
		}
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody,
			"caller.jwt", "attribute-key", headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "client-a", "writer-a")
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		for index := range 20 {
			name := fmt.Sprintf("attribute%02d", index)
			Expect(headerValue(echo.Headers, fmt.Sprintf("X-Attribute%02d", index))).To(Equal(values[name]), name)
		}
	}, NodeTimeout(60*time.Second))

	It("denies missing attributes before the backend, including when output headers are spoofed", func(ctx SpecContext) {
		for _, index := range []int{0, 9, 19} {
			name := fmt.Sprintf("attribute%02d", index)
			expectAPIKeyDenied(ctx, gateway, "missing "+name, apiKeyOnlyHost, false, "", fmt.Sprintf("missing-%02d", index), http.Header{
				"X-Auth-Gateway-API-Key-Client":       []string{name + "=spoofed"},
				fmt.Sprintf("X-Attribute%02d", index): []string{"spoofed"},
			}, http.StatusForbidden)
		}
	}, NodeTimeout(60*time.Second))
})
