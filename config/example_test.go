package config_test

import (
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
  image: envoyproxy/envoy:v1.39.1
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

	for _, filename := range slices.Sorted(maps.Keys(files)) {
		outputPath := filepath.Join(outputDirectory, filename)
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(outputPath, files[filename], 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Println(filename)
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
