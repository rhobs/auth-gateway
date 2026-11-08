package envoy_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/rhobs/auth-gateway/pkg/config"
	"github.com/rhobs/auth-gateway/pkg/envoy"
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

func ExampleGenerate() {
	gateway, err := config.Load(strings.NewReader(exampleGatewayYAML))
	if err != nil {
		log.Fatal(err)
	}

	files, err := envoy.Generate(gateway)
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

func exampleOutputDirectory() (string, func(), error) {
	directory, err := os.MkdirTemp("", "auth-gateway-example-")
	if err != nil {
		return "", nil, err
	}
	return directory, func() { _ = os.RemoveAll(directory) }, nil
}
