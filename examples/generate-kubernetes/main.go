package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/rhobs/auth-gateway/config"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <config.yaml> <manifest.yaml>\n", os.Args[0])
		os.Exit(2)
	}
	if err := generateManifest(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generateManifest(configPath, manifestPath string) error {
	input, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %q: %w", configPath, err)
	}
	cfg, err := config.Load(bytes.NewReader(input))
	if err != nil {
		return fmt.Errorf("load config %q: %w", configPath, err)
	}
	resources, err := config.GenerateKubernetes(cfg)
	if err != nil {
		return fmt.Errorf("generate Kubernetes resources: %w", err)
	}
	manifest, err := resources.YAML()
	if err != nil {
		return fmt.Errorf("encode Kubernetes resources: %w", err)
	}
	if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
		return fmt.Errorf("write manifest %q: %w", manifestPath, err)
	}
	return nil
}
