//go:build e2e

package framework

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
)

// Diagnostics saves Kubernetes objects and recent container logs under e2e/.state.
func (e *Environment) Diagnostics(namespace string) {
	if e == nil {
		return
	}
	dir := e.StatePath("artifacts", time.Now().UTC().Format("20060102T150405.000000000"))
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintln(GinkgoWriter, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	core := e.client.CoreV1()

	pods, err := core.Pods(namespace).List(ctx, metav1.ListOptions{})
	writeDiagnostic(dir, "pods.json", pods, err)
	if err == nil {
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				tailLines := int64(40)
				logOptions := &corev1.PodLogOptions{Container: container.Name, TailLines: &tailLines}
				data, err := core.Pods(namespace).GetLogs(pod.Name, logOptions).Do(ctx).Raw()
				writeDiagnostic(dir, pod.Name+"-"+container.Name+".log", data, err)
			}
		}
	}

	services, err := core.Services(namespace).List(ctx, metav1.ListOptions{})
	writeDiagnostic(dir, "services.json", services, err)
	if endpoints, err := core.Endpoints(namespace).Get(ctx, "httpbin", metav1.GetOptions{}); err == nil {
		writeDiagnostic(dir, "httpbin-endpoints.json", endpoints, nil)
	} else {
		writeDiagnostic(dir, "httpbin-endpoints.json", nil, err)
	}
	deployments, err := e.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	writeDiagnostic(dir, "deployments.json", deployments, err)
	events, err := core.Events(namespace).List(ctx, metav1.ListOptions{})
	writeDiagnostic(dir, "events.json", events, err)
	fmt.Fprintf(GinkgoWriter, "Failure diagnostics: %s\n", dir)
}

func writeDiagnostic(dir, name string, value any, err error) {
	var data []byte
	if err != nil {
		data = []byte("error: " + err.Error() + "\n")
	} else if raw, ok := value.([]byte); ok {
		data = raw
	} else {
		var marshalErr error
		data, marshalErr = json.MarshalIndent(value, "", "  ")
		if marshalErr != nil {
			data = []byte("encode diagnostic: " + marshalErr.Error() + "\n")
		} else {
			data = append(data, '\n')
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		fmt.Fprintf(GinkgoWriter, "write diagnostic %s: %v\n", name, err)
	}
}
