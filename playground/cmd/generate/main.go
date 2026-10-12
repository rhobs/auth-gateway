package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rhobs/auth-gateway/config"
)

func main() {
	configPath := flag.String("config", "config.yaml", "gateway configuration file")
	outputDirectory := flag.String("output", "generated", "directory for generated files")
	printImageDefaults := flag.Bool("print-image-defaults", false, "print the default Envoy and collector images")
	flag.Parse()

	if *printImageDefaults {
		fmt.Println(config.DefaultEnvoyImage, config.DefaultOTelCollectorImage)
		return
	}

	if err := generate(*configPath, *outputDirectory); err != nil {
		fmt.Fprintf(os.Stderr, "generate playground files: %v\n", err)
		os.Exit(1)
	}
}

func generate(configPath, outputDirectory string) error {
	input, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("open config %q: %w", configPath, err)
	}
	gatewayConfig, loadErr := config.Load(input)
	closeErr := input.Close()
	if loadErr != nil {
		return fmt.Errorf("load config %q: %w", configPath, loadErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close config %q: %w", configPath, closeErr)
	}

	envoyFiles, err := config.Generate(gatewayConfig)
	if err != nil {
		return fmt.Errorf("generate Envoy files: %w", err)
	}
	collectorConfig, err := config.GenerateOTelCollectorConfig(gatewayConfig)
	if err != nil {
		return fmt.Errorf("generate collector config: %w", err)
	}
	if len(collectorConfig) == 0 {
		return fmt.Errorf("gateway config must enable metrics or tracing to generate the collector config")
	}

	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return fmt.Errorf("create output directory %q: %w", outputDirectory, err)
	}
	for _, file := range envoyFiles.All() {
		relativePath, err := filepath.Rel(config.EnvoyConfigDirectory, file.Path)
		if err != nil {
			return fmt.Errorf("make generated path %q relative: %w", file.Path, err)
		}
		outputPath := filepath.Join(outputDirectory, filepath.FromSlash(relativePath))
		if err := writeGeneratedFile(outputPath, file.Contents); err != nil {
			return err
		}
	}
	if err := writeGeneratedFile(filepath.Join(outputDirectory, "otel-collector.yaml"), collectorConfig); err != nil {
		return err
	}
	return nil
}

func writeGeneratedFile(filePath string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return fmt.Errorf("create directory for %q: %w", filePath, err)
	}
	if err := os.WriteFile(filePath, contents, 0o644); err != nil {
		return fmt.Errorf("write generated file %q: %w", filePath, err)
	}
	return nil
}
