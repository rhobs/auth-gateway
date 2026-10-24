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
	"slices"
	"testing"
	"time"
)

func TestPinnedImagesValidateGoldenFiles(t *testing.T) {
	certificate, key := runtimeCertificate(t)
	goldenPaths, err := filepath.Glob(filepath.Join("testdata", "*", "envoy.yaml.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if len(goldenPaths) == 0 {
		t.Fatal("no Envoy golden files found")
	}
	for _, goldenPath := range goldenPaths {
		name := filepath.Base(filepath.Dir(goldenPath))
		t.Run(name, func(t *testing.T) {
			c := loadConfigCase(t, name)
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			validatePinnedEnvoyFiles(t, c, files, filepath.Dir(goldenPath), certificate, key)
			if name == "production-tuning" {
				validatePinnedCollectorConfig(t, c)
			}
		})
	}
	t.Run("playground", func(t *testing.T) {
		configPath := filepath.Join("..", "playground", "config.yaml")
		c := loadTestConfig(t, readTestFile(t, configPath), configPath)
		files, err := Generate(c)
		if err != nil {
			t.Fatal(err)
		}
		validatePinnedEnvoyFiles(t, c, files, filepath.Join("..", "playground"), certificate, key)
	})
	t.Run("tracing", func(t *testing.T) {
		c := loadConfigCase(t, "public-routing")
		c.Observability.Tracing = ObservabilityTracing{
			Enabled:            new(true),
			Endpoint:           "jaeger:4317",
			ServiceName:        "auth-gateway-runtime",
			SamplingPercentage: new(100.0),
			Insecure:           new(true),
		}
		files, err := Generate(c)
		if err != nil {
			t.Fatal(err)
		}
		validatePinnedEnvoyFiles(t, c, files, "", certificate, key)
		validatePinnedCollectorConfig(t, c)
	})
}

func validatePinnedEnvoyFiles(t *testing.T, c Config, files GeneratedFiles, goldenDirectory string, certificate, key []byte) {
	t.Helper()
	effective := resolveTestConfig(t, c)
	args := []string{"run", "--rm", "--user", "101:101"}
	configDir := runtimeDirectory(t)
	externalFiles := make(map[string]map[string][]byte)
	if _, exists := effective.apiKeyAuthenticator(); exists {
		if err := os.Mkdir(filepath.Join(configDir, "api-keys"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range files.All() {
		contents := file.Contents
		if goldenDirectory != "" {
			goldenPath := filepath.Join(goldenDirectory, filepath.Base(file.Path)+".golden")
			golden, err := os.ReadFile(goldenPath)
			if err == nil {
				contents = golden
			} else if file.Path == EnvoyBootstrapPath && os.IsNotExist(err) {
				t.Fatalf("read Envoy bootstrap golden %s: %v", goldenPath, err)
			} else if !os.IsNotExist(err) {
				t.Fatalf("read Envoy golden %s: %v", goldenPath, err)
			}
		}
		relativePath, err := filepath.Rel(EnvoyConfigDirectory, filepath.FromSlash(file.Path))
		if err != nil {
			t.Fatalf("make generated path relative: %v", err)
		}
		outputPath := filepath.Join(configDir, relativePath)
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			t.Fatal(err)
		}
		runtimeWrite(t, outputPath, contents)
	}
	if authenticator, exists := effective.apiKeyAuthenticator(); exists {
		data, err := GenerateAPIKeyECDS(authenticator, nil)
		if err != nil {
			t.Fatal(err)
		}
		runtimeWrite(t, filepath.Join(configDir, "api-keys", apiKeySecretFilename), data)
	}
	for _, mount := range c.tlsMounts() {
		writeRuntimeMountedFile(t, configDir, externalFiles, mount.config.Certificate, certificate)
		writeRuntimeMountedFile(t, configDir, externalFiles, mount.config.PrivateKey, key)
	}
	for _, ca := range effective.caMounts() {
		dir := runtimeDirectory(t)
		runtimeWrite(t, filepath.Join(dir, "ca.crt"), certificate)
		args = append(args, "-v", dir+":"+filepath.Join(caDirectory, ca.id())+":ro")
	}
	for _, filename := range runtimeTrustedCAFiles(effective) {
		writeRuntimeMountedFile(t, configDir, externalFiles, filename, certificate)
	}
	args = append(args, "-v", configDir+":"+configDirectory+":ro")
	directories := make([]string, 0, len(externalFiles))
	for directory := range externalFiles {
		directories = append(directories, directory)
	}
	slices.Sort(directories)
	for _, directory := range directories {
		dir := runtimeDirectory(t)
		filenames := make([]string, 0, len(externalFiles[directory]))
		for filename := range externalFiles[directory] {
			filenames = append(filenames, filename)
		}
		slices.Sort(filenames)
		for _, filename := range filenames {
			runtimeWrite(t, filepath.Join(dir, filename), externalFiles[directory][filename])
		}
		args = append(args, "-v", dir+":"+directory+":ro")
	}
	image := os.Getenv("AUTH_GATEWAY_RUNTIME_IMAGE")
	if image == "" {
		image = DefaultEnvoyImage
	}
	runtimeDocker(t, append(args, image, "--mode", "validate", "-c", configDirectory+"/envoy.yaml", "--log-level", "error")...)
}

func writeRuntimeMountedFile(t *testing.T, configDir string, externalFiles map[string]map[string][]byte, filename string, contents []byte) {
	t.Helper()
	relative, err := filepath.Rel(configDirectory, filename)
	if err != nil {
		t.Fatalf("make runtime file path relative: %v", err)
	}
	if filepath.IsLocal(relative) {
		runtimeWrite(t, filepath.Join(configDir, relative), contents)
		return
	}
	directory := filepath.Dir(filename)
	if externalFiles[directory] == nil {
		externalFiles[directory] = make(map[string][]byte)
	}
	externalFiles[directory][filepath.Base(filename)] = contents
}

func runtimeTrustedCAFiles(c effectiveConfig) []string {
	var filenames []string
	seen := make(map[string]struct{})
	add := func(ca *TrustedCA) {
		if ca == nil || ca.Filename == "" {
			return
		}
		if _, exists := seen[ca.Filename]; exists {
			return
		}
		seen[ca.Filename] = struct{}{}
		filenames = append(filenames, ca.Filename)
	}
	for _, authenticator := range c.Authenticators {
		if !c.authenticatorUsed(authenticator.Name) {
			continue
		}
		if authenticator.JWT != nil {
			add(authenticator.JWT.JWKS.TrustedCA)
		}
		if authenticator.MTLS != nil {
			add(authenticator.MTLS.TrustedCA)
		}
	}
	for _, api := range c.APIs {
		if api.Upstream.TLSConfig != nil {
			add(api.Upstream.TLSConfig.TrustedCA)
		}
	}
	return filenames
}

func validatePinnedCollectorConfig(t *testing.T, c Config) {
	t.Helper()
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	dir := runtimeDirectory(t)
	runtimeWrite(t, filepath.Join(dir, "config.yaml"), []byte(r.OTelCollectorConfigMap.Data["config.yaml"]))
	runtimeDocker(t, "run", "--rm", "-v", dir+":/etc/collector:ro", DefaultOTelCollectorImage, "validate", "--config=/etc/collector/config.yaml")
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
