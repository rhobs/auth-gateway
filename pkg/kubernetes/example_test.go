package kubernetes_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/rhobs/auth-gateway/pkg/api"
	"github.com/rhobs/auth-gateway/pkg/config"
	"github.com/rhobs/auth-gateway/pkg/kubernetes"
)

const exampleKubernetesGatewayYAML = `version: 1
servers:
  - hostname: auth.example.com
    apis: [metrics]
apis:
  - name: metrics
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - methods: [POST]
        path:
          exact: /metrics/api/v1/receive
kubernetes:
  name: auth-gateway
  namespace: observability
  image: registry.example.com/envoyproxy/envoy:approved
  otel_collector_image: registry.example.com/opentelemetry/collector:approved
`

func ExampleGenerate() {
	gateway, err := config.Load(strings.NewReader(exampleKubernetesGatewayYAML))
	if err != nil {
		log.Fatal(err)
	}

	resources, err := kubernetes.Generate(gateway)
	if err != nil {
		log.Fatal(err)
	}

	manifest, err := resources.YAML()
	if err != nil {
		log.Fatal(err)
	}

	outputDirectory, cleanup, err := exampleOutputDirectory()
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()

	manifestPath := filepath.Join(outputDirectory, "auth-gateway.yaml")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println(filepath.Base(manifestPath))
	// Output: auth-gateway.yaml
}

func ExampleAPIKeySecret() {
	credentials, err := config.LoadAPIKeyCredentials(strings.NewReader(`credentials:
  - key: example-partner-key
`))
	if err != nil {
		log.Fatal(err)
	}

	authenticator := api.Authenticator{
		Name:   "partner-key",
		APIKey: &api.APIKeyAuthenticator{Secret: "auth-gateway-api-keys"},
	}
	secret, err := kubernetes.APIKeySecret("observability", authenticator, credentials)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(secret.Name, secret.Namespace)
	fmt.Println(len(secret.Data) > 0)
	// Output:
	// auth-gateway-api-keys observability
	// true
}

func exampleOutputDirectory() (string, func(), error) {
	directory, err := os.MkdirTemp("", "auth-gateway-example-")
	if err != nil {
		return "", nil, err
	}
	return directory, func() { _ = os.RemoveAll(directory) }, nil
}
