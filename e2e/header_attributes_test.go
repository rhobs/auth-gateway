//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const (
	headerJWTOnlyHost   = "jwt.header-attributes.auth-gateway.test"
	headerKeyOnlyHost   = "key.header-attributes.auth-gateway.test"
	headerAttributeBody = "header-attribute-payload"
)

var headerAttributesNamespace = e2eNamespace("auth-gateway-header-attributes-e2e")

var _ = Describe("Header-to-credential tenant equality", Label("gateway", "authentication", "authorization", "header-attributes", "namespace-"+headerAttributesNamespace), Ordered, func() {
	var gateway *apiKeyE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(headerAttributesNamespace) })
		var err error
		gateway, err = setupAPIKeyGatewayWithShape(ctx, headerAttributesNamespace, false, []gatewayapi.APIKeyCredential{
			{Key: "header-key", Attributes: map[string]string{"tenant_id": "client-a", "writer_id": "writer-a"}},
			{Key: "header-key-b", Attributes: map[string]string{"tenant_id": "client-b", "writer_id": "writer-b"}},
		}, "header-key", shapeHeaderAttributeGateway)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("forwards each authorized requested tenant from the original header and records it in metrics", func(ctx SpecContext) {
		for _, tenant := range []string{"client-a", "client-b"} {
			for _, method := range []string{"jwt", "api-key"} {
				host, source, token, key := headerJWTOnlyHost, "X-JWT-Tenant", gateway.token(tenant, "writer-a"), ""
				if method == "api-key" {
					host, source, token, key = headerKeyOnlyHost, "X-Key-Tenant", "", "header-key"
					if tenant == "client-b" {
						key = "header-key-b"
					}
				}
				labels := map[string]string{"api": "header-ingest", "http_status_code": strconv.Itoa(http.StatusOK), "tenant": tenant}
				before, err := requestMetricCount(ctx, gateway.adminAddr, labels)
				Expect(err).NotTo(HaveOccurred())
				headers := http.Header{source: []string{tenant}, "X-Forwarded-Tenant": []string{"caller-controlled"}}
				status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-header-ingest", method+" "+tenant, 1, func() (int, []byte, error) {
					return gateway.request(ctx, host, false, http.MethodPost, "/header-ingest", headerAttributeBody, token, key, headers)
				})
				Expect(status).To(Equal(http.StatusOK), string(body))
				expectHeaderAttributeEcho(body, tenant, map[string]string{source: tenant})
				after, err := requestMetricCount(ctx, gateway.adminAddr, labels)
				Expect(err).NotTo(HaveOccurred())
				Expect(after).To(BeNumerically(">", before))
			}
		}
	}, NodeTimeout(2*time.Minute))

	It("denies absent credentials and unmatched or unequal tenants before the backend", func(ctx SpecContext) {
		for _, method := range []string{"jwt", "api-key"} {
			host, source, token, key := headerJWTOnlyHost, "X-JWT-Tenant", gateway.token("client-a", "writer-a"), ""
			if method == "api-key" {
				host, source, token, key = headerKeyOnlyHost, "X-Key-Tenant", "", "header-key"
			}
			for _, test := range []struct {
				name              string
				values            []string
				missingCredential bool
				status            int
			}{
				{name: "missing credential", values: []string{"client-a"}, missingCredential: true, status: http.StatusUnauthorized},
				{name: "missing header", status: http.StatusForbidden},
				{name: "empty header", values: []string{""}, status: http.StatusForbidden},
				{name: "unlisted tenant", values: []string{"client-c"}, status: http.StatusForbidden},
				{name: "another listed tenant", values: []string{"client-b"}, status: http.StatusForbidden},
				{name: "duplicate tenant header", values: []string{"client-a", "client-b"}, status: http.StatusBadRequest},
				{name: "identical repeated tenant", values: []string{"client-a", "client-a"}, status: http.StatusBadRequest},
				{name: "comma-separated tenant", values: []string{"client-a,client-b"}, status: http.StatusBadRequest},
			} {
				headers := http.Header{"X-Forwarded-Tenant": []string{"client-a"}}
				if test.values != nil {
					headers[source] = test.values
				}
				requestToken, requestKey := token, key
				if test.missingCredential {
					requestToken, requestKey = "", ""
				}
				expectHeaderAttributeDenied(ctx, gateway, method+" "+test.name, host, requestToken, requestKey, headers, test.status)
			}
		}
	}, NodeTimeout(2*time.Minute))

	It("requires a nonempty scalar JWT tenant for equality", func(ctx SpecContext) {
		for _, tenant := range []any{nil, "", []string{"client-a"}, 123, map[string]any{"id": "client-a"}} {
			claims := map[string]any{"organization": map[string]any{"id": tenant}, "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix()}
			token := (&jwtE2E{keys: gateway.keys}).token("issuer-one", claims, nil)
			expectHeaderAttributeDenied(ctx, gateway, "non-scalar or empty tenant", headerJWTOnlyHost, token, "", http.Header{"X-JWT-Tenant": []string{"client-a"}}, http.StatusForbidden)
		}
	}, NodeTimeout(90*time.Second))
})

func shapeHeaderAttributeGateway(c *gatewayapi.Config) {
	setE2EAttribute(&c.Authenticators[0], gatewayapi.AttributeSource{Name: "requested_tenant", FromSource: "header", Value: gatewayapi.AttributeValue{Text: "X-JWT-Tenant"}})
	setE2EAttribute(&c.Authenticators[1], gatewayapi.AttributeSource{Name: "requested_tenant", FromSource: "header", Value: gatewayapi.AttributeValue{Text: "X-Key-Tenant"}})
	c.APIs = append(c.APIs, gatewayapi.API{
		Name:     "header-ingest",
		Metrics:  &gatewayapi.APIMetrics{Labels: map[string]string{"tenant": "requested_tenant"}},
		Upstream: gatewayapi.Upstream{Address: "httpbin", Port: 8080},
		Routes:   []gatewayapi.Route{{Methods: []string{http.MethodPost}, Path: gatewayapi.PathMatch{Exact: "/header-ingest"}, Rewrite: &gatewayapi.PathRewrite{Path: "/anything"}, Processing: &gatewayapi.RouteProcessing{RequestHeaders: []gatewayapi.RequestHeaderMapping{{Name: "X-Forwarded-Tenant", FromAttribute: "requested_tenant"}}}}},
	})
	for _, method := range []struct {
		host, header, authenticator string
		authentication              gatewayapi.Authentication
	}{
		{headerJWTOnlyHost, "X-JWT-Tenant", "issuer-one", gatewayapi.Authentication{JWT: &gatewayapi.JWTAuthentication{Providers: []string{"issuer-one"}}}},
		{headerKeyOnlyHost, "X-Key-Tenant", "partner-key", gatewayapi.Authentication{APIKey: &gatewayapi.AuthenticatorReference{Authenticator: "partner-key"}}},
	} {
		c.Servers = append(c.Servers, gatewayapi.Server{Hostname: method.host, APIs: []gatewayapi.APIBinding{{Name: "header-ingest", Access: []gatewayapi.Access{{Name: "writers", Match: gatewayapi.AccessMatch{Headers: map[string]gatewayapi.HeaderMatch{method.header: {In: []string{"client-a", "client-b"}}}}, Authentication: &method.authentication, Authorization: gatewayapi.Authorization{Grants: []gatewayapi.AuthorizationGrant{{Authenticator: method.authenticator, Attributes: map[string]*gatewayapi.AttributeCondition{"tenant_id": {EqualsAttribute: "requested_tenant"}}}}}}}}}})
	}
}

func setE2EAttribute(authenticator *gatewayapi.Authenticator, source gatewayapi.AttributeSource) {
	for i := range authenticator.Attributes {
		if authenticator.Attributes[i].Name == source.Name {
			authenticator.Attributes[i] = source
			return
		}
	}
	authenticator.Attributes = append(authenticator.Attributes, source)
}

func expectHeaderAttributeEcho(body []byte, tenant string, sourceHeaders map[string]string) {
	echo, err := decodeHTTPBinEcho(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(echo.Method).To(Equal(http.MethodPost))
	Expect(echo.URL).To(HaveSuffix("/anything"))
	Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(headerAttributeBody))))
	Expect(headerValue(echo.Headers, "X-Forwarded-Tenant")).To(Equal(tenant))
	for name, value := range sourceHeaders {
		Expect(headerValue(echo.Headers, name)).To(Equal(value), name)
	}
	for _, name := range []string{"Authorization", "X-Partner-Key", "X-Auth-Gateway-API-Key-Client", "X-Auth-Gateway-Request-Validation-Pending"} {
		Expect(headerValue(echo.Headers, name)).To(BeEmpty(), name+" leaked to the backend")
	}
}

func expectHeaderAttributeDenied(ctx context.Context, gateway *apiKeyE2E, name, host, token, key string, headers http.Header, wantStatus int) {
	expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-header-ingest", name, wantStatus, func() (int, []byte, error) {
		return gateway.request(ctx, host, false, http.MethodPost, "/header-ingest", headerAttributeBody, token, key, headers)
	})
}
