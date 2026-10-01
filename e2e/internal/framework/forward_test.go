//go:build e2e

package framework

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveServicePortForwardTargetUsesReadyPodAndNamedTargetPort(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "auth-gateway", Namespace: "test"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "gateway"},
				Ports:    []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromString("http")}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "a-unready", Namespace: "test", Labels: map[string]string{"app": "gateway"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "gateway", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "z-ready", Namespace: "test", Labels: map[string]string{"app": "gateway"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "gateway", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}}},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		},
	)
	env := &Environment{client: client}

	pod, port, err := env.resolvePortForwardTarget(ctx, "test", "service/auth-gateway", 443)
	if err != nil {
		t.Fatalf("resolve port-forward target: %v", err)
	}
	if pod.Name != "z-ready" {
		t.Fatalf("selected Pod %q, want ready Pod %q", pod.Name, "z-ready")
	}
	if port != 8080 {
		t.Fatalf("selected Pod port %d, want 8080", port)
	}
}

func TestChooseRunningPodExcludesTerminatingPods(t *testing.T) {
	now := metav1.Now()
	_, err := chooseRunningPod([]corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "terminating", DeletionTimestamp: &now},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}}, "test Deployment")
	if err == nil {
		t.Fatal("expected an error when all matching Pods are terminating")
	}
}
