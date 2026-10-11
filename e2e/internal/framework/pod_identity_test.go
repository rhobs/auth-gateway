//go:build e2e

package framework

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPodIdentityAccessorsReturnSortedNonTerminatingPods(t *testing.T) {
	now := metav1.Now()
	client := fake.NewClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "gateway-z", Namespace: "test", UID: "uid-z", Labels: map[string]string{"app": "gateway"},
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "gateway-a", Namespace: "test", UID: "uid-a", Labels: map[string]string{"app": "gateway"},
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "gateway-deleting", Namespace: "test", UID: "uid-old", Labels: map[string]string{"app": "gateway"}, DeletionTimestamp: &now,
		}},
	)
	env := &Environment{client: client}

	identities, err := env.PodIdentities(context.Background(), "test", "app=gateway")
	if err != nil {
		t.Fatalf("read Pod identities: %v", err)
	}
	wantIdentities := []PodIdentity{{Name: "gateway-a", UID: "uid-a"}, {Name: "gateway-z", UID: "uid-z"}}
	if !slices.Equal(identities, wantIdentities) {
		t.Fatalf("Pod identities = %v, want %v", identities, wantIdentities)
	}

	uids, err := env.PodUIDs(context.Background(), "test", "app=gateway")
	if err != nil {
		t.Fatalf("read Pod UIDs: %v", err)
	}
	if want := []string{"uid-a", "uid-z"}; !slices.Equal(uids, want) {
		t.Fatalf("Pod UIDs = %v, want %v", uids, want)
	}

	names, err := env.PodNames(context.Background(), "test", "app=gateway")
	if err != nil {
		t.Fatalf("read Pod names: %v", err)
	}
	if want := []string{"gateway-a", "gateway-z"}; !slices.Equal(names, want) {
		t.Fatalf("Pod names = %v, want %v", names, want)
	}
}
