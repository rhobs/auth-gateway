package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestGenerateSecretWritesPrivateManifestAndExplicitRevocation(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	outputPath := filepath.Join(dir, "secret.yaml")
	configPath := filepath.Join("..", "..", "config", "testdata", "api-key-auth", "config.yaml")
	for _, test := range []struct {
		name        string
		credentials string
		want        []byte
	}{
		{name: "credential", credentials: "credentials:\n  - key: example-key\n    attributes:\n      tenant_id: client-a\n      writer_id: writer-a\n", want: []byte("example-key")},
		{name: "revocation", credentials: "credentials: []\n", want: []byte("credentials: []")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(credentialsPath, []byte(test.credentials), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := generateSecret(configPath, credentialsPath, outputPath); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("Secret manifest mode = %o, want 600", info.Mode().Perm())
			}
			manifest, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			var secret corev1.Secret
			if err := yaml.Unmarshal(manifest, &secret); err != nil {
				t.Fatal(err)
			}
			if secret.Name != "gateway-api-keys" || secret.Namespace != "gateway-test" ||
				!bytes.Contains(secret.Data["api-keys.yaml"], test.want) {
				t.Fatalf("generated Secret identity or ECDS data = %q/%q, %s", secret.Name, secret.Namespace, secret.Data["api-keys.yaml"])
			}
		})
	}
}
