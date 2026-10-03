//go:build e2e

package framework

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultCertManagerManifest = "https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml"

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
