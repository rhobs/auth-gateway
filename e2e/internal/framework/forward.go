//go:build e2e

package framework

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type requestContextTransport struct {
	next http.RoundTripper
	ctx  context.Context
}

func (t requestContextTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.next.RoundTrip(request.WithContext(t.ctx))
}

func chooseRunningPod(pods []corev1.Pod, owner string) (*corev1.Pod, error) {
	var running []corev1.Pod
	for _, pod := range pods {
		if pod.Status.Phase == corev1.PodRunning && pod.DeletionTimestamp == nil {
			running = append(running, pod)
		}
	}
	if len(running) == 0 {
		return nil, fmt.Errorf("%s has no Running Pods", owner)
	}
	sort.Slice(running, func(i, j int) bool {
		if podReady(&running[i]) != podReady(&running[j]) {
			return podReady(&running[i])
		}
		return running[i].Name < running[j].Name
	})
	return &running[0], nil
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func resolveTargetPort(targetPort intstr.IntOrString, servicePort int32, pod *corev1.Pod) (int32, error) {
	switch targetPort.Type {
	case intstr.Int:
		if targetPort.IntVal == 0 {
			return servicePort, nil
		}
		return targetPort.IntVal, nil
	case intstr.String:
		if targetPort.StrVal == "" {
			return servicePort, nil
		}
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.Name == targetPort.StrVal {
					return port.ContainerPort, nil
				}
			}
		}
		return 0, fmt.Errorf("Pod %q has no container port named %q", pod.Name, targetPort.StrVal)
	default:
		return 0, fmt.Errorf("invalid target port type %d", targetPort.Type)
	}
}
