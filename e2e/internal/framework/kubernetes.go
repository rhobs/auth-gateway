//go:build e2e

package framework

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
)

const fieldManager = "auth-gateway-e2e"

// Apply decodes YAML documents and applies each object with server-side apply.
func (e *Environment) Apply(ctx context.Context, namespace string, manifest []byte) error {
	return e.apply(ctx, namespace, manifest, false)
}

// ApplyWithForce applies objects and takes ownership of fields managed by other field managers.
func (e *Environment) ApplyWithForce(ctx context.Context, namespace string, manifest []byte) error {
	return e.apply(ctx, namespace, manifest, true)
}

func (e *Environment) apply(ctx context.Context, namespace string, manifest []byte, force bool) error {
	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(manifest), 4096)
	for document := 1; ; document++ {
		var object map[string]interface{}
		if err := decoder.Decode(&object); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("decode manifest document %d: %w", document, err)
		}
		if len(object) == 0 {
			continue
		}
		resource := &unstructured.Unstructured{Object: object}
		if resource.GetAPIVersion() == "" || resource.GetKind() == "" || resource.GetName() == "" {
			return fmt.Errorf("manifest document %d must define apiVersion, kind, and metadata.name", document)
		}
		groupVersion, err := schema.ParseGroupVersion(resource.GetAPIVersion())
		if err != nil {
			return fmt.Errorf("manifest document %d has invalid apiVersion %q: %w", document, resource.GetAPIVersion(), err)
		}
		gvk := groupVersion.WithKind(resource.GetKind())
		mapping, err := e.restMapping(gvk)
		if err != nil {
			return fmt.Errorf("map %s %q: %w", gvk.String(), resource.GetName(), err)
		}

		resourceClient := e.dynamic.Resource(mapping.Resource)
		var client dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			if resource.GetNamespace() == "" {
				resource.SetNamespace(namespace)
			}
			if resource.GetNamespace() == "" {
				return fmt.Errorf("manifest document %d is namespaced but no namespace was provided", document)
			}
			client = resourceClient.Namespace(resource.GetNamespace())
		} else if resource.GetNamespace() != "" {
			return fmt.Errorf("manifest document %d is cluster-scoped but declares namespace %q", document, resource.GetNamespace())
		} else {
			client = resourceClient
		}

		data, err := json.Marshal(resource.Object)
		if err != nil {
			return fmt.Errorf("encode %s %q: %w", gvk.String(), resource.GetName(), err)
		}
		patchOptions := metav1.PatchOptions{FieldManager: fieldManager}
		if force {
			patchOptions.Force = &force
		}
		if _, err := client.Patch(ctx, resource.GetName(), types.ApplyPatchType, data, patchOptions); err != nil {
			return fmt.Errorf("apply %s %q: %w", gvk.String(), resource.GetName(), err)
		}
	}
}

func (e *Environment) restMapping(gvk schema.GroupVersionKind) (*meta.RESTMapping, error) {
	e.mapperMu.Lock()
	defer e.mapperMu.Unlock()

	mapping, err := e.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if !meta.IsNoMatchError(err) {
		return mapping, err
	}
	// CRDs may have been installed after the mapper first queried discovery.
	e.mapper.Reset()
	return e.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
}

func (e *Environment) DeleteNamespace(ctx context.Context, namespace string) error {
	err := e.client.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete Namespace %q: %w", namespace, err)
	}
	if err := utilwait.PollUntilContextTimeout(ctx, time.Second, 120*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := e.client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}); err != nil {
		return fmt.Errorf("wait for Namespace %q deletion: %w", namespace, err)
	}
	return nil
}

func (e *Environment) CreateNamespace(ctx context.Context, namespace string) error {
	_, err := e.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create Namespace %q: %w", namespace, err)
	}
	return nil
}

// WaitForResourceCondition polls a namespaced resource until the named condition is True.
func (e *Environment) WaitForResourceCondition(ctx context.Context, namespace string, resource schema.GroupVersionResource, name, conditionType string, timeout time.Duration) error {
	err := utilwait.PollUntilContextTimeout(ctx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		object, err := e.dynamic.Resource(resource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		conditions, found, err := unstructured.NestedSlice(object.Object, "status", "conditions")
		if err != nil || !found {
			return false, err
		}
		for _, item := range conditions {
			condition, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if condition["type"] == conditionType && condition["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("wait for %s %q condition %s=True: %w", resource.Resource, name, conditionType, err)
	}
	return nil
}

// WaitForDeployment waits until the requested Deployment generation is available.
func (e *Environment) WaitForDeployment(ctx context.Context, namespace, name string, timeout time.Duration) error {
	err := utilwait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		deployment, err := e.client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if deploymentFailed(deployment) {
			return false, fmt.Errorf("Deployment %q exceeded its progress deadline", name)
		}
		desired := int32(1)
		if deployment.Spec.Replicas != nil {
			desired = *deployment.Spec.Replicas
		}
		complete := deployment.Status.ObservedGeneration >= deployment.Generation &&
			deployment.Status.UpdatedReplicas >= desired &&
			deployment.Status.AvailableReplicas >= desired &&
			deployment.Status.UnavailableReplicas == 0
		return complete, nil
	})
	if err != nil {
		return fmt.Errorf("wait for Deployment %q rollout: %w", name, err)
	}
	return nil
}

// RestartDeployment changes a pod-template annotation and waits for the replacement Pods to become available.
func (e *Environment) RestartDeployment(ctx context.Context, namespace, name string, timeout time.Duration) error {
	deployment, err := e.client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get Deployment %q before restart: %w", name, err)
	}
	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["auth-gateway-e2e/restarted-at"] = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := e.client.AppsV1().Deployments(namespace).Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("restart Deployment %q: %w", name, err)
	}
	return e.WaitForDeployment(ctx, namespace, name, timeout)
}

func deploymentFailed(deployment *appsv1.Deployment) bool {
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == appsv1.DeploymentProgressing &&
			condition.Status == corev1.ConditionFalse &&
			condition.Reason == "ProgressDeadlineExceeded" {
			return true
		}
	}
	return false
}

func (e *Environment) Secret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	secret, err := e.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get Secret %q: %w", name, err)
	}
	return secret, nil
}

func (e *Environment) PodUID(ctx context.Context, namespace, labelSelector string) (string, error) {
	pods, err := e.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return "", fmt.Errorf("list Pods matching %q: %w", labelSelector, err)
	}
	if len(pods.Items) != 1 || pods.Items[0].UID == "" {
		return "", fmt.Errorf("expected one Pod matching %q, got %d", labelSelector, len(pods.Items))
	}
	return string(pods.Items[0].UID), nil
}
