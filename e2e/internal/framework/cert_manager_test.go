//go:build e2e

package framework

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestWaitForCertManagerWebhookRetriesDryRunIssuer(t *testing.T) {
	attempts := 0
	client := issuerAdmissionClientFunc(func(_ context.Context, name string, patchType types.PatchType, data []byte, options metav1.PatchOptions, _ ...string) (*unstructured.Unstructured, error) {
		attempts++
		if name != certManagerWebhookReadinessProbeName {
			return nil, errors.New("readiness probe used an unexpected Issuer name")
		}
		if patchType != types.ApplyPatchType || string(data) != certManagerWebhookReadinessProbeRequest {
			return nil, errors.New("readiness probe did not use the expected Issuer apply patch")
		}
		if options.FieldManager != fieldManager || len(options.DryRun) != 1 || options.DryRun[0] != metav1.DryRunAll {
			return nil, errors.New("readiness probe was not a dry-run apply")
		}
		if attempts == 1 {
			return nil, errors.New("webhook is not ready")
		}
		return &unstructured.Unstructured{}, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := waitForIssuerAdmissionWebhook(ctx, client, time.Second); err != nil {
		t.Fatalf("wait for webhook: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("dry-run Issuer attempts = %d, want 2", attempts)
	}
}

type issuerAdmissionClientFunc func(context.Context, string, types.PatchType, []byte, metav1.PatchOptions, ...string) (*unstructured.Unstructured, error)

func (f issuerAdmissionClientFunc) Patch(ctx context.Context, name string, patchType types.PatchType, data []byte, options metav1.PatchOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return f(ctx, name, patchType, data, options, subresources...)
}
