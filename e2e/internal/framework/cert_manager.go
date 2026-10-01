//go:build e2e

package framework

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultCertManagerManifest = "https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml"

// EnsureCertManager installs the cert-manager manifest and waits for its controllers.
func (e *Environment) EnsureCertManager(ctx context.Context, manifestSource string) error {
	if manifestSource == "" {
		manifestSource = defaultCertManagerManifest
	}
	manifest, err := readManifest(ctx, manifestSource)
	if err != nil {
		return err
	}
	if err := e.ApplyWithForce(ctx, "", manifest); err != nil {
		return fmt.Errorf("apply cert-manager manifest: %w", err)
	}
	for _, deployment := range []string{"cert-manager", "cert-manager-cainjector", "cert-manager-webhook"} {
		if err := e.WaitForDeployment(ctx, "cert-manager", deployment, 4*time.Minute); err != nil {
			return err
		}
	}
	return nil
}

// RenewCertificate delegates manual renewal to cmctl, which owns the cert-manager renewal semantics.
func (e *Environment) RenewCertificate(ctx context.Context, namespace, name string) error {
	if namespace == "" || name == "" {
		return fmt.Errorf("renew Certificate requires a namespace and name")
	}
	cmctlPath := os.Getenv("AUTH_GATEWAY_E2E_CMCTL")
	if cmctlPath == "" {
		cmctlPath = "cmctl"
	}
	args := []string{"renew", "--context", e.KubeContext(), "--namespace", namespace, name}
	output, err := exec.CommandContext(ctx, cmctlPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmctl %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return nil
}

func readManifest(ctx context.Context, source string) ([]byte, error) {
	parsed, err := url.Parse(source)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return os.ReadFile(source)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, fmt.Errorf("create cert-manager manifest request: %w", err)
	}
	response, err := (&http.Client{Timeout: 2 * time.Minute}).Do(request)
	if err != nil {
		return nil, fmt.Errorf("download cert-manager manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download cert-manager manifest: HTTP %s", response.Status)
	}
	manifest, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read cert-manager manifest: %w", err)
	}
	if strings.TrimSpace(string(manifest)) == "" {
		return nil, fmt.Errorf("cert-manager manifest is empty")
	}
	return manifest, nil
}
