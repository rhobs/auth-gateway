package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rhobs/auth-gateway/config"
	"go.yaml.in/yaml/v3"
	k8syaml "sigs.k8s.io/yaml"
)

type credentialsDocument struct {
	Credentials *[]config.APIKeyCredential `yaml:"credentials"`
}

const decodeCredentialsErrorFormat = "decode credentials %q: %w"

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <config.yaml> <credentials.yaml> <secret.yaml>\n", os.Args[0])
		os.Exit(2)
	}
	if err := generateSecret(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generateSecret(configPath, credentialsPath, outputPath string) error {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %q: %w", configPath, err)
	}
	c, err := config.Load(bytes.NewReader(configData))
	if err != nil {
		return fmt.Errorf("load config %q: %w", configPath, err)
	}
	if c.Kubernetes == nil {
		return fmt.Errorf("kubernetes settings are required to name the Secret namespace")
	}
	var authenticator *config.Authenticator
	for i := range c.Authenticators {
		if c.Authenticators[i].APIKey != nil {
			authenticator = &c.Authenticators[i]
			break
		}
	}
	if authenticator == nil {
		return fmt.Errorf("config has no API-key authenticator")
	}
	credentialsData, err := os.ReadFile(credentialsPath)
	if err != nil {
		return fmt.Errorf("read credentials %q: %w", credentialsPath, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(credentialsData))
	decoder.KnownFields(true)
	var input credentialsDocument
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf(decodeCredentialsErrorFormat, credentialsPath, err)
	}
	if input.Credentials == nil {
		return fmt.Errorf("credentials document must set credentials (use [] to revoke all keys)")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("credentials document must contain exactly one YAML document")
	} else if err != io.EOF {
		return fmt.Errorf(decodeCredentialsErrorFormat, credentialsPath, err)
	}
	secret, err := config.APIKeySecret(c.Kubernetes.Namespace, *authenticator, *input.Credentials)
	if err != nil {
		return err
	}
	manifest, err := k8syaml.Marshal(secret)
	if err != nil {
		return fmt.Errorf("encode API-key Secret: %w", err)
	}
	output, err := os.CreateTemp(filepath.Dir(outputPath), ".api-key-secret-*.yaml")
	if err != nil {
		return fmt.Errorf("create Secret output: %w", err)
	}
	defer func() { _ = os.Remove(output.Name()) }()
	if _, err := output.Write(manifest); err != nil {
		return errors.Join(fmt.Errorf("write Secret output: %w", err), output.Close())
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close Secret output: %w", err)
	}
	if err := os.Rename(output.Name(), outputPath); err != nil {
		return fmt.Errorf("replace Secret output: %w", err)
	}
	return nil
}
