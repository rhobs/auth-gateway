//go:build envoyruntime

package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedImagesValidateGeneratedFiles(t *testing.T) {
	certificate, key := runtimeCertificate(t)
	for _, name := range []string{"public-routing", "route-lists", "server-tls", "jwt-auth", "jwt-auth-with-headers", "jwt-auth-with-mappings", "jwt-auth-multiple-issuers", "api-key-auth", "header-attributes", "production-tuning"} {
		t.Run(name, func(t *testing.T) {
			c := loadConfigCase(t, name)
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"run", "--rm", "--user", "101:101"}
			configDir := runtimeDirectory(t)
			processingDir := filepath.Join(configDir, "processing")
			if err := os.Mkdir(processingDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if _, exists := c.apiKeyAuthenticator(); exists {
				if err := os.Mkdir(filepath.Join(configDir, "api-keys"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for name, data := range files {
				dir := configDir
				if name == processingConfigFilename {
					dir = processingDir
				}
				runtimeWrite(t, filepath.Join(dir, name), data)
			}
			if authenticator, exists := c.apiKeyAuthenticator(); exists {
				secret, err := APIKeySecret(c.Kubernetes.Namespace, authenticator, nil)
				if err != nil {
					t.Fatal(err)
				}
				runtimeWrite(t, filepath.Join(configDir, "api-keys", apiKeySecretFilename), secret.Data[apiKeySecretFilename])
			}
			args = append(args, "-v", configDir+":"+configDirectory+":ro")
			for _, mount := range c.tlsMounts() {
				dir := runtimeDirectory(t)
				runtimeWrite(t, filepath.Join(dir, filepath.Base(mount.config.Certificate)), certificate)
				runtimeWrite(t, filepath.Join(dir, filepath.Base(mount.config.PrivateKey)), key)
				args = append(args, "-v", dir+":"+filepath.Dir(mount.config.Certificate)+":ro")
			}
			for _, ca := range c.caMounts() {
				dir := runtimeDirectory(t)
				runtimeWrite(t, filepath.Join(dir, "ca.crt"), certificate)
				args = append(args, "-v", dir+":"+filepath.Join(caDirectory, ca.id())+":ro")
			}
			image := os.Getenv("AUTH_GATEWAY_RUNTIME_IMAGE")
			if image == "" {
				image = "envoyproxy/envoy:v1.39.1"
			}
			runtimeDocker(t, append(args, image, "--mode", "validate", "-c", configDirectory+"/envoy.yaml", "--log-level", "error")...)
			if name == "production-tuning" {
				r, err := GenerateKubernetes(c)
				if err != nil {
					t.Fatal(err)
				}
				dir := runtimeDirectory(t)
				runtimeWrite(t, filepath.Join(dir, "config.yaml"), []byte(r.OTelCollectorConfigMap.Data["config.yaml"]))
				runtimeDocker(t, "run", "--rm", "-v", dir+":/etc/collector:ro", defaultOTelCollectorImage, "validate", "--config=/etc/collector/config.yaml")
			}
		})
	}
}

func runtimeDocker(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("pinned-image validation: %v\n%s", err, output)
	}
}

func runtimeDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runtimeWrite(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func runtimeCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "runtime-test"}, DNSNames: []string{"gateway.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}
