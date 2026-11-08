package gateway

import (
	"slices"
	"testing"
)

func TestEnvoyConcurrencyGeneration(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes.EnvoyConcurrency = new(uint32(3))
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	args := r.Deployment.Spec.Template.Spec.Containers[0].Args
	index := slices.Index(args, "--concurrency")
	if index < 0 || index+1 == len(args) || args[index+1] != "3" {
		t.Fatalf("Envoy args = %v", args)
	}
	c.Kubernetes.EnvoyConcurrency = nil
	c.Kubernetes.Resources.Limits["cpu"] = "4"
	r, err = GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.Deployment.Spec.Template.Spec.Containers[0].Args, "--concurrency") {
		t.Fatal("worker count inferred from CPU limit")
	}
}
