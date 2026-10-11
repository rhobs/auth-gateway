//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rhobs/auth-gateway/config"
)

const (
	headerJWTOnlyHost   = "jwt.header-attributes.auth-gateway.test"
	headerKeyOnlyHost   = "key.header-attributes.auth-gateway.test"
	headerAnyHost       = "any.header-attributes.auth-gateway.test"
	headerAllHost       = "all.header-attributes.auth-gateway.test"
	headerAttributeBody = "header-attribute-payload"
)

var headerAttributesNamespace = e2eNamespace("auth-gateway-header-attributes-e2e")

var _ = Describe("Header-sourced attributes", Label("gateway", "authentication", "authorization", "header-attributes", "namespace-"+headerAttributesNamespace), Ordered, func() {
	var gateway *apiKeyE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, headerAttributesNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		gateway, err = setupAPIKeyGatewayWithShape(ctx, headerAttributesNamespace, false, []config.APIKeyCredential{{
			Key: "header-key", Attributes: map[string]string{"tenant_id": "client-a", "writer_id": "writer-a"},
		}}, "header-key", shapeHeaderAttributeGateway)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("uses header-only JWT and key grants while forwarding mapped and original values", func(ctx SpecContext) {
		for _, test := range []struct {
			name   string
			host   string
			token  string
			key    string
			header string
		}{
			{name: "JWT", host: headerJWTOnlyHost, token: gateway.token("client-a", "writer-a"), header: "X-JWT-Tenant"},
			{name: "API key", host: headerKeyOnlyHost, key: "header-key", header: "X-Key-Tenant"},
		} {
			headers := http.Header{test.header: []string{"client-a"}}
			status, body, err := gateway.request(ctx, test.host, false, http.MethodPost, "/header-ingest", headerAttributeBody, test.token, test.key, headers)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			expectHeaderAttributeEcho(body, "team-a", map[string]string{test.header: "client-a"})
		}
	}, NodeTimeout(90*time.Second))

	It("denies absent credentials and missing or unlisted header values before the backend", func(ctx SpecContext) {
		jwt := gateway.token("client-a", "writer-a")
		for _, test := range []struct {
			name    string
			host    string
			token   string
			key     string
			headers http.Header
			status  int
		}{
			{name: "JWT credential missing", host: headerJWTOnlyHost, headers: http.Header{"X-JWT-Tenant": []string{"client-a"}}, status: http.StatusUnauthorized},
			{name: "JWT credential invalid", host: headerJWTOnlyHost, token: "invalid.jwt", headers: http.Header{"X-JWT-Tenant": []string{"client-a"}}, status: http.StatusUnauthorized},
			{name: "JWT header missing", host: headerJWTOnlyHost, token: jwt, status: http.StatusForbidden},
			{name: "JWT header empty", host: headerJWTOnlyHost, token: jwt, headers: http.Header{"X-JWT-Tenant": []string{""}}, status: http.StatusForbidden},
			{name: "JWT header unlisted", host: headerJWTOnlyHost, token: jwt, headers: http.Header{"X-JWT-Tenant": []string{"client-c"}}, status: http.StatusForbidden},
			{name: "key missing", host: headerKeyOnlyHost, headers: http.Header{"X-Key-Tenant": []string{"client-a"}}, status: http.StatusUnauthorized},
			{name: "key invalid", host: headerKeyOnlyHost, key: "unknown-key", headers: http.Header{"X-Key-Tenant": []string{"client-a"}}, status: http.StatusUnauthorized},
			{name: "key header missing", host: headerKeyOnlyHost, key: "header-key", status: http.StatusForbidden},
			{name: "key header empty", host: headerKeyOnlyHost, key: "header-key", headers: http.Header{"X-Key-Tenant": []string{""}}, status: http.StatusForbidden},
			{name: "key header unlisted", host: headerKeyOnlyHost, key: "header-key", headers: http.Header{"X-Key-Tenant": []string{"client-c"}}, status: http.StatusForbidden},
		} {
			expectHeaderAttributeDenied(ctx, gateway, test.name, test.host, test.token, test.key, test.headers, test.status)
		}
	}, NodeTimeout(2*time.Minute))

	It("keeps the verified JWT working value on mixed any_of", func(ctx SpecContext) {
		headers := http.Header{"X-JWT-Tenant": []string{"client-a"}, "X-Key-Tenant": []string{"client-b"}}
		status, body, err := gateway.request(ctx, headerAnyHost, false, http.MethodPost, "/header-ingest", headerAttributeBody,
			gateway.token("client-a", "writer-a"), "header-key", headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectHeaderAttributeEcho(body, "team-a", map[string]string{"X-JWT-Tenant": "client-a", "X-Key-Tenant": "client-b"})

		expectHeaderAttributeDenied(ctx, gateway, "valid but unprivileged JWT wins", headerAnyHost,
			gateway.token("client-a", "writer-a"), "header-key",
			http.Header{"X-JWT-Tenant": []string{"client-c"}, "X-Key-Tenant": []string{"client-a"}}, http.StatusForbidden)

		status, body, err = gateway.request(ctx, headerAnyHost, false, http.MethodPost, "/header-ingest", headerAttributeBody,
			"invalid.jwt", "header-key", http.Header{"X-JWT-Tenant": []string{"client-b"}, "X-Key-Tenant": []string{"client-a"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectHeaderAttributeEcho(body, "team-a", map[string]string{"X-JWT-Tenant": "client-b", "X-Key-Tenant": "client-a"})
	}, NodeTimeout(90*time.Second))

	It("requires matching nonempty raw values across headers, claims, and key credentials on all_of", func(ctx SpecContext) {
		jwt := gateway.token("client-a", "writer-a")
		matching := http.Header{"X-JWT-Tenant": []string{"client-a"}, "X-Key-Tenant": []string{"client-a"}}
		status, body, err := gateway.request(ctx, headerAllHost, false, http.MethodPost, "/header-ingest", headerAttributeBody, jwt, "header-key", matching)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectHeaderAttributeEcho(body, "team-a", map[string]string{"X-JWT-Tenant": "client-a", "X-Key-Tenant": "client-a"})

		for _, test := range []struct {
			name    string
			token   string
			key     string
			headers http.Header
			status  int
		}{
			{name: "JWT missing", key: "header-key", headers: matching, status: http.StatusUnauthorized},
			{name: "key missing", token: jwt, headers: matching, status: http.StatusUnauthorized},
			{name: "header missing", token: jwt, key: "header-key", headers: http.Header{"X-JWT-Tenant": []string{"client-a"}}, status: http.StatusForbidden},
			{name: "header mismatch", token: jwt, key: "header-key", headers: http.Header{"X-JWT-Tenant": []string{"client-b"}, "X-Key-Tenant": []string{"client-a"}}, status: http.StatusForbidden},
			{name: "claim and header mismatch", token: jwt, key: "header-key", headers: http.Header{"X-JWT-Tenant": []string{"client-b"}, "X-Key-Tenant": []string{"client-b"}}, status: http.StatusForbidden},
		} {
			expectHeaderAttributeDenied(ctx, gateway, test.name, headerAllHost, test.token, test.key, test.headers, test.status)
		}
	}, NodeTimeout(90*time.Second))

	It("reloads header mappings without changing the Pod or raw grant", func(ctx SpecContext) {
		oldUID, err := gatewayPodUID(ctx, headerAttributesNamespace)
		Expect(err).NotTo(HaveOccurred())
		updatedConfig, err := apiKeyConfig(headerAttributesNamespace, false)
		Expect(err).NotTo(HaveOccurred())
		shapeHeaderAttributeGateway(&updatedConfig)
		updatedConfig.Processing[0].Attributes["requested_tenant"].Mappings["client-a"] = "team-c"
		updated, err := config.GenerateKubernetes(updatedConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.ConfigMap.Data).To(Equal(gateway.resources.ConfigMap.Data))
		Expect(updated.Deployment.Spec.Template).To(Equal(gateway.resources.Deployment.Spec.Template))
		Expect(updated.ProcessingConfigMap.Data).NotTo(Equal(gateway.resources.ProcessingConfigMap.Data))
		manifest, err := yamlDocuments(updated.ProcessingConfigMap)
		Expect(err).NotTo(HaveOccurred())
		timeE2EPhase("header mapping resource apply", func() {
			Expect(env.Apply(ctx, headerAttributesNamespace, manifest)).To(Succeed())
		})

		labels := map[string]string{"api": "header-ingest", "http_status_code": strconv.Itoa(http.StatusOK), "tenant": "team-c"}
		before, err := requestMetricCount(ctx, gateway.adminAddr, labels)
		Expect(err).NotTo(HaveOccurred())
		headers := http.Header{"X-JWT-Tenant": []string{"client-a"}}
		var status int
		var body []byte
		timeE2EPhase("header mapping apply-to-observed reload", func() {
			Eventually(func() bool {
				status, body, err = gateway.request(ctx, headerJWTOnlyHost, false, http.MethodPost, "/header-ingest", headerAttributeBody,
					gateway.token("client-a", "writer-a"), "", headers)
				return err == nil && status == http.StatusOK && headerValue(jwtEchoHeaders(body), "X-Processed-Tenant") == "team-c"
			}).WithContext(ctx).WithTimeout(3*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
				return fmt.Sprintf("header mapping did not reload: HTTP %d: %s (error: %v)", status, body, err)
			})
		})
		timeE2EPhase("header mapping post-reload assertions", func() {
			expectHeaderAttributeEcho(body, "team-c", map[string]string{"X-JWT-Tenant": "client-a"})
			after, err := requestMetricCount(ctx, gateway.adminAddr, labels)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(BeNumerically(">", before))
			newUID, err := gatewayPodUID(ctx, headerAttributesNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(newUID).To(Equal(oldUID))
		})
	}, SpecTimeout(4*time.Minute))
})

func shapeHeaderAttributeGateway(c *config.Config) {
	c.Authenticators[0].Attributes["requested_tenant"] = headerAttributeSource("X-JWT-Tenant")
	c.Authenticators[0].Attributes["tenant_check"] = config.AttributeSource{ClaimPath: []string{"organization", "id"}}
	c.Authenticators[1].Attributes["requested_tenant"] = headerAttributeSource("X-Key-Tenant")
	c.Authenticators[1].Attributes["tenant_check"] = headerAttributeSource("X-Key-Tenant")
	c.AuthorizationPolicies = append(c.AuthorizationPolicies, config.AuthorizationPolicy{
		Name: "header-writers",
		Grants: []config.AuthorizationGrant{
			{Authenticator: "issuer-one", APIs: []string{"header-ingest"}, Attributes: map[string][]string{"requested_tenant": {"client-a", "client-b"}}},
			{Authenticator: "partner-key", APIs: []string{"header-ingest"}, Attributes: map[string][]string{"requested_tenant": {"client-a", "client-b"}}},
		},
	})
	c.APIs = append(c.APIs, config.API{
		Name:     "header-ingest",
		Metrics:  &config.APIMetrics{Labels: map[string]string{"tenant": "requested_tenant"}},
		Upstream: config.Upstream{Address: "httpbin", Port: 8080},
		Routes: []config.Route{{
			Methods:    []string{http.MethodPost},
			Path:       config.PathMatch{Exact: "/header-ingest"},
			Rewrite:    &config.PathRewrite{Path: "/anything"},
			Processing: &config.RouteProcessing{RequestHeaders: []config.RequestHeaderMapping{{Name: "X-Processed-Tenant", FromAttribute: "requested_tenant"}}},
		}},
	})
	c.Servers = append(c.Servers, []config.Server{
		{Hostname: headerJWTOnlyHost, Authentication: &config.Authentication{AnyOf: []string{"issuer-one"}}, Authorization: &config.Authorization{AnyOf: []string{"header-writers"}}, APIs: []string{"header-ingest"}},
		{Hostname: headerKeyOnlyHost, Authentication: &config.Authentication{AnyOf: []string{"partner-key"}}, Authorization: &config.Authorization{AnyOf: []string{"header-writers"}}, APIs: []string{"header-ingest"}},
		{Hostname: headerAnyHost, Authentication: &config.Authentication{AnyOf: []string{"issuer-one", "partner-key"}}, Authorization: &config.Authorization{AnyOf: []string{"header-writers"}}, APIs: []string{"header-ingest"}},
		{Hostname: headerAllHost, Authentication: &config.Authentication{AllOf: []string{"issuer-one", "partner-key"}}, Authorization: &config.Authorization{AllOf: []string{"header-writers"}}, APIs: []string{"header-ingest"}},
	}...)
	c.Processing[0].Attributes["requested_tenant"] = config.AttributeMappings{Mappings: map[string]string{"client-a": "team-a", "client-b": "team-b"}}
}

func headerAttributeSource(header string) config.AttributeSource {
	return config.AttributeSource{Header: &header}
}

func expectHeaderAttributeEcho(body []byte, mapped string, sourceHeaders map[string]string) {
	echo, err := decodeHTTPBinEcho(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(echo.Method).To(Equal(http.MethodPost))
	Expect(echo.URL).To(HaveSuffix("/anything"))
	Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(headerAttributeBody))))
	Expect(headerValue(echo.Headers, "X-Processed-Tenant")).To(Equal(mapped))
	for name, value := range sourceHeaders {
		Expect(headerValue(echo.Headers, name)).To(Equal(value), name)
	}
	for _, name := range []string{"Authorization", "X-Partner-Key", "X-Auth-Gateway-API-Key-Client", "X-Auth-Gateway-JWT-Verified-Issuer-One"} {
		Expect(headerValue(echo.Headers, name)).To(BeEmpty(), name+" leaked to the backend")
	}
}

func expectHeaderAttributeDenied(ctx context.Context, gateway *apiKeyE2E, name, host, token, key string, headers http.Header, wantStatus int) {
	expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-header-ingest", name, wantStatus, func() (int, []byte, error) {
		return gateway.request(ctx, host, false, http.MethodPost, "/header-ingest", headerAttributeBody, token, key, headers)
	})
}
