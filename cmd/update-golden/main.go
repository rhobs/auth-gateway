package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rhobs/auth-gateway/config"
)

var cases = []string{
	"public-routing",
	"route-lists",
	"server-tls",
	"jwt-auth",
	"jwt-auth-with-headers",
	"jwt-auth-with-mappings",
	"jwt-auth-multiple-issuers",
}

func main() {
	if err := update(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func update() error {
	for _, name := range cases {
		casePath := filepath.Join("config", "testdata", name)
		input, err := os.Open(filepath.Join(casePath, "config.yaml"))
		if err != nil {
			return fmt.Errorf("open %s case: %w", name, err)
		}
		gatewayConfig, err := config.Load(input)
		closeErr := input.Close()
		if err != nil {
			return fmt.Errorf("load %s case: %w", name, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s case: %w", name, closeErr)
		}

		envoyFiles, err := config.Generate(gatewayConfig)
		if err != nil {
			return fmt.Errorf("generate %s Envoy output: %w", name, err)
		}
		if err := write(filepath.Join(casePath, "envoy.yaml.golden"), envoyFiles["envoy.yaml"]); err != nil {
			return err
		}
		processingGolden := filepath.Join(casePath, "processing.yaml.golden")
		if processingData, ok := envoyFiles["processing.yaml"]; ok {
			if err := write(processingGolden, processingData); err != nil {
				return err
			}
		} else if err := os.Remove(processingGolden); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale %s processing reference: %w", name, err)
		}

		resources, err := config.GenerateKubernetes(gatewayConfig)
		if err != nil {
			return fmt.Errorf("generate %s Kubernetes output: %w", name, err)
		}
		manifest, err := resources.YAML()
		if err != nil {
			return fmt.Errorf("serialize %s Kubernetes output: %w", name, err)
		}
		if err := write(filepath.Join(casePath, "kubernetes.yaml.golden"), manifest); err != nil {
			return err
		}
		fmt.Printf("updated %s reference outputs\n", name)
	}
	return nil
}

func write(filename string, data []byte) error {
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filename, err)
	}
	return nil
}
