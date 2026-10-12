//go:build e2e

package framework

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
)

const (
	defaultCertManagerManifest               = "https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml"
	certManagerWebhookReadinessTimeout       = 2 * time.Minute
	certManagerWebhookReadinessProbeName     = "auth-gateway-webhook-readiness"
	certManagerWebhookReadinessProbeInterval = 500 * time.Millisecond
	certManagerWebhookReadinessProbeRequest  = `{"apiVersion":"cert-manager.io/v1","kind":"Issuer","metadata":{"name":"auth-gateway-webhook-readiness","namespace":"default"},"spec":{"selfSigned":{}}}`
)

func readManifest(ctx context.Context, source string) (manifest []byte, resultErr error) {
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
	defer func() {
		if err := response.Body.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close cert-manager manifest response: %w", err))
		}
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download cert-manager manifest: HTTP %s", response.Status)
	}
	manifest, err = io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read cert-manager manifest: %w", err)
	}
	if strings.TrimSpace(string(manifest)) == "" {
		return nil, fmt.Errorf("cert-manager manifest is empty")
	}
	return manifest, nil
}

func (e *Environment) waitForCertManagerWebhook(ctx context.Context, timeout time.Duration) error {
	issuers := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}
	client := e.dynamic.Resource(issuers).Namespace("default")
	return waitForIssuerAdmissionWebhook(ctx, client, timeout)
}

type issuerAdmissionClient interface {
	Patch(ctx context.Context, name string, patchType types.PatchType, data []byte, options metav1.PatchOptions, subresources ...string) (*unstructured.Unstructured, error)
}

func waitForIssuerAdmissionWebhook(ctx context.Context, client issuerAdmissionClient, timeout time.Duration) error {
	var lastErr error
	err := utilwait.PollUntilContextTimeout(ctx, certManagerWebhookReadinessProbeInterval, timeout, true, func(ctx context.Context) (bool, error) {
		_, lastErr = client.Patch(ctx, certManagerWebhookReadinessProbeName, types.ApplyPatchType, []byte(certManagerWebhookReadinessProbeRequest), metav1.PatchOptions{
			FieldManager: fieldManager,
			DryRun:       []string{metav1.DryRunAll},
		})
		return lastErr == nil, nil
	})
	if err != nil {
		if lastErr != nil {
			return fmt.Errorf("wait for cert-manager admission webhook: %w (last dry-run Issuer error: %v)", err, lastErr)
		}
		return fmt.Errorf("wait for cert-manager admission webhook: %w", err)
	}
	return nil
}
