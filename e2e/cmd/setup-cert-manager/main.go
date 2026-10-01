//go:build e2e

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rhobs/auth-gateway/e2e/internal/framework"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	manifestSource := flag.String("manifest", "", "cert-manager manifest URL or local path")
	flag.Parse()
	if *manifestSource == "" {
		return fmt.Errorf("-manifest is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	env, err := framework.New()
	if err != nil {
		return err
	}
	manifest, err := readManifest(ctx, *manifestSource)
	if err != nil {
		return err
	}
	// Reusable Kind clusters may have fields owned by the earlier client-side kubectl installer.
	if err := env.ApplyWithForce(ctx, "", manifest); err != nil {
		return fmt.Errorf("apply cert-manager manifest: %w", err)
	}
	for _, deployment := range []string{"cert-manager", "cert-manager-cainjector", "cert-manager-webhook"} {
		if err := env.WaitForDeployment(ctx, "cert-manager", deployment, 4*time.Minute); err != nil {
			return err
		}
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
		return nil, fmt.Errorf("create manifest request: %w", err)
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
