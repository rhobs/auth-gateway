package config_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rhobs/auth-gateway/config"
)

const exampleGatewayYAML = `version: 1
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
`

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

func exampleOutputDirectory() (string, func(), error) {
	directory, err := os.MkdirTemp("", "auth-gateway-example-")
	if err != nil {
		return "", nil, err
	}
	return directory, func() { _ = os.RemoveAll(directory) }, nil
}

func ExampleLoad() {
	gateway, err := config.Load(strings.NewReader(exampleGatewayYAML))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(gateway.APIs[0].Name)
	// Output: metrics
}

func ExampleGenerate() {
	gateway, err := config.Load(strings.NewReader(exampleGatewayYAML))
	if err != nil {
		log.Fatal(err)
	}

	files, err := config.Generate(gateway)
	if err != nil {
		log.Fatal(err)
	}

	outputDirectory, cleanup, err := exampleOutputDirectory()
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()

	for _, file := range files.All() {
		relativePath := strings.TrimPrefix(filepath.FromSlash(file.Path), string(filepath.Separator))
		outputPath := filepath.Join(outputDirectory, relativePath)
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(outputPath, file.Contents, 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Println(filepath.Base(file.Path))
	}
	// Output: envoy.yaml
}

func ExampleGenerateKubernetes() {
	gateway, err := config.Load(strings.NewReader(exampleKubernetesGatewayYAML))
	if err != nil {
		log.Fatal(err)
	}

	resources, err := config.GenerateKubernetes(gateway)
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

	authenticator := config.Authenticator{
		Name:   "partner-key",
		APIKey: &config.APIKeyAuthenticator{Secret: "auth-gateway-api-keys"},
	}
	secret, err := config.APIKeySecret("observability", authenticator, credentials)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(secret.Name, secret.Namespace)
	fmt.Println(len(secret.Data) > 0)
	// Output:
	// auth-gateway-api-keys observability
	// true
}

func ExampleNewDuration() {
	gateway := config.Config{
		Version: 1,
		Listener: config.Listener{
			Port:           new(uint32(8080)),
			RequestTimeout: config.NewDuration(30 * time.Second),
		},
		Servers: []config.Server{{
			Hostname: "metrics.example.com",
			APIs:     []string{"metrics"},
		}},
		APIs: []config.API{{
			Name: "metrics",
			Upstream: config.Upstream{
				Address:        "thanos-receive",
				Port:           19291,
				ConnectTimeout: config.NewDuration(5 * time.Second),
			},
			Routes: []config.Route{{
				Methods: []string{"POST"},
				Path:    config.PathMatch{Exact: "/metrics/api/v1/receive"},
			}},
		}},
	}
	if err := gateway.Validate(); err != nil {
		log.Fatal(err)
	}

	fmt.Println(gateway.Listener.RequestTimeout)
	fmt.Println(gateway.APIs[0].Upstream.ConnectTimeout)
	// Output:
	// 30s
	// 5s
}
