//go:build e2e

package framework

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const defaultClusterContext = "kind-auth-gateway-e2e"

// Environment scopes Kubernetes clients and fixture paths to one cluster.
type Environment struct {
	Root           string
	ClusterContext string

	config   *rest.Config
	client   kubernetes.Interface
	dynamic  dynamic.Interface
	mapper   *restmapper.DeferredDiscoveryRESTMapper
	mapperMu sync.Mutex
}

func New() (*Environment, error) {
	root, err := Root()
	if err != nil {
		return nil, err
	}
	clusterContext := os.Getenv("AUTH_GATEWAY_E2E_CONTEXT")
	if clusterContext == "" {
		clusterContext = defaultClusterContext
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: clusterContext},
	)
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes context %q: %w", clusterContext, err)
	}
	config = rest.CopyConfig(config)
	config.Timeout = 20 * time.Second

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic Kubernetes client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes discovery client: %w", err)
	}

	return &Environment{
		Root:           root,
		ClusterContext: clusterContext,
		config:         config,
		client:         client,
		dynamic:        dynamicClient,
		mapper:         restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(discoveryClient)),
	}, nil
}

// Root finds the repository root from the current directory or one of its parents.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		fixture := filepath.Join(dir, "e2e", "fixtures", "gateway.yaml")
		if info, err := os.Stat(fixture); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("run from the repository or e2e directory")
		}
		dir = parent
	}
}

func (e *Environment) KubeContext() string {
	if e.ClusterContext == "" {
		return defaultClusterContext
	}
	return e.ClusterContext
}

func (e *Environment) Fixture(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(e.Root, "e2e", "fixtures", name))
}

func (e *Environment) StatePath(parts ...string) string {
	return filepath.Join(append([]string{e.Root, "e2e", ".state", e.KubeContext()}, parts...)...)
}

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

// EnsureCertManager installs the cert-manager manifest and waits for its controllers.
func (e *Environment) EnsureCertManager(ctx context.Context, manifestSource string) error {
	if manifestSource == "" {
		manifestSource = defaultCertManagerManifest
	}
	manifest, err := readManifest(ctx, manifestSource)
	if err != nil {
		return err
	}
	if err := e.ApplyWithForce(ctx, "", manifest); err != nil {
		return fmt.Errorf("apply cert-manager manifest: %w", err)
	}
	for _, deployment := range []string{"cert-manager", "cert-manager-cainjector", "cert-manager-webhook"} {
		if err := e.WaitForDeployment(ctx, "cert-manager", deployment, 4*time.Minute); err != nil {
			return err
		}
	}
	return nil
}

// RenewCertificate delegates manual renewal to cmctl, which owns the cert-manager renewal semantics.
func (e *Environment) RenewCertificate(ctx context.Context, namespace, name string) error {
	if namespace == "" || name == "" {
		return fmt.Errorf("renew Certificate requires a namespace and name")
	}
	cmctlPath := os.Getenv("AUTH_GATEWAY_E2E_CMCTL")
	if cmctlPath == "" {
		cmctlPath = "cmctl"
	}
	args := []string{"renew", "--context", e.KubeContext(), "--namespace", namespace, name}
	output, err := exec.CommandContext(ctx, cmctlPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmctl %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return nil
}

// Forward opens a loopback-only port forward to a Pod selected from a Service,
// Deployment, or Pod reference such as service/auth-gateway.
func (e *Environment) Forward(ctx context.Context, namespace, resource string, remotePort int) (address string, stop func(), err error) {
	if remotePort < 1 || remotePort > 65535 {
		return "", nil, fmt.Errorf("invalid remote port %d", remotePort)
	}
	pod, podPort, err := e.resolvePortForwardTarget(ctx, namespace, resource, remotePort)
	if err != nil {
		return "", nil, err
	}

	transport, upgrader, err := spdy.RoundTripperFor(e.config)
	if err != nil {
		return "", nil, fmt.Errorf("create port-forward transport: %w", err)
	}
	dialContext, cancelDial := context.WithTimeout(context.Background(), time.Minute)
	defer cancelDial()
	url := e.client.CoreV1().RESTClient().Post().
		Namespace(namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("portforward").URL()
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: requestContextTransport{next: transport, ctx: dialContext}}, http.MethodPost, url)

	stopChannel := make(chan struct{})
	readyChannel := make(chan struct{})
	var stderr bytes.Buffer
	forwarder, err := portforward.NewOnAddresses(
		dialer,
		[]string{"127.0.0.1"},
		[]string{fmt.Sprintf("0:%d", podPort)},
		stopChannel,
		readyChannel,
		io.Discard,
		&stderr,
	)
	if err != nil {
		return "", nil, fmt.Errorf("configure port-forward to Pod %q: %w", pod.Name, err)
	}

	done := make(chan struct{})
	var forwardErr error
	go func() {
		forwardErr = forwarder.ForwardPorts()
		close(done)
	}()

	var stopOnce sync.Once
	stop = func() {
		stopOnce.Do(func() {
			cancelDial()
			close(stopChannel)
			<-done
		})
	}

	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	select {
	case <-readyChannel:
		cancelDial()
		ports, err := forwarder.GetPorts()
		if err != nil {
			stop()
			return "", nil, fmt.Errorf("get forwarded port for Pod %q: %w", pod.Name, err)
		}
		if len(ports) != 1 {
			stop()
			return "", nil, fmt.Errorf("expected one forwarded port for Pod %q, got %d", pod.Name, len(ports))
		}
		return fmt.Sprintf("127.0.0.1:%d", ports[0].Local), stop, nil
	case <-done:
		cancelDial()
		return "", nil, fmt.Errorf("port-forward %s to Pod %q: %v\n%s", resource, pod.Name, forwardErr, stderr.String())
	case <-ctx.Done():
		stop()
		return "", nil, ctx.Err()
	case <-timer.C:
		stop()
		return "", nil, fmt.Errorf("port-forward %s to Pod %q timed out: %s", resource, pod.Name, stderr.String())
	}
}

func (e *Environment) resolvePortForwardTarget(ctx context.Context, namespace, resource string, remotePort int) (*corev1.Pod, int32, error) {
	kind, name, ok := strings.Cut(resource, "/")
	if !ok || kind == "" || name == "" {
		return nil, 0, fmt.Errorf("resource %q must be kind/name", resource)
	}

	switch kind {
	case "service":
		service, err := e.client.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, 0, fmt.Errorf("get Service %q: %w", name, err)
		}
		var servicePort *corev1.ServicePort
		for i := range service.Spec.Ports {
			if int(service.Spec.Ports[i].Port) == remotePort {
				servicePort = &service.Spec.Ports[i]
				break
			}
		}
		if servicePort == nil {
			return nil, 0, fmt.Errorf("Service %q has no port %d", name, remotePort)
		}
		if len(service.Spec.Selector) == 0 {
			return nil, 0, fmt.Errorf("Service %q has no Pod selector", name)
		}
		pods, err := e.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set(service.Spec.Selector).AsSelector().String()})
		if err != nil {
			return nil, 0, fmt.Errorf("list Pods for Service %q: %w", name, err)
		}
		pod, err := chooseRunningPod(pods.Items, fmt.Sprintf("Service %q", name))
		if err != nil {
			return nil, 0, err
		}
		podPort, err := resolveTargetPort(servicePort.TargetPort, int32(servicePort.Port), pod)
		if err != nil {
			return nil, 0, fmt.Errorf("resolve Service %q target port: %w", name, err)
		}
		return pod, podPort, nil

	case "deployment":
		deployment, err := e.client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, 0, fmt.Errorf("get Deployment %q: %w", name, err)
		}
		selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
		if err != nil {
			return nil, 0, fmt.Errorf("get Pod selector for Deployment %q: %w", name, err)
		}
		pods, err := e.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
		if err != nil {
			return nil, 0, fmt.Errorf("list Pods for Deployment %q: %w", name, err)
		}
		pod, err := chooseRunningPod(pods.Items, fmt.Sprintf("Deployment %q", name))
		if err != nil {
			return nil, 0, err
		}
		return pod, int32(remotePort), nil

	case "pod":
		pod, err := e.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, 0, fmt.Errorf("get Pod %q: %w", name, err)
		}
		if pod.Status.Phase != corev1.PodRunning {
			return nil, 0, fmt.Errorf("Pod %q is %s, not Running", name, pod.Status.Phase)
		}
		return pod, int32(remotePort), nil

	default:
		return nil, 0, fmt.Errorf("unsupported port-forward resource kind %q", kind)
	}
}

// ForwardWithCleanup registers the port forward for Ginkgo cleanup.
func (e *Environment) ForwardWithCleanup(ctx context.Context, namespace, resource string, remotePort int) string {
	GinkgoHelper()
	address, stop, err := e.Forward(ctx, namespace, resource, remotePort)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(stop)
	return address
}

// Diagnostics saves Kubernetes objects, recent container logs, and Envoy cluster state under e2e/.state.
func (e *Environment) Diagnostics(namespace string) {
	if e == nil || namespace == "" {
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
	e.envoyClusterDiagnostics(namespace, dir)
	fmt.Fprintf(GinkgoWriter, "Failure diagnostics: %s\n", dir)
}

func (e *Environment) envoyClusterDiagnostics(namespace, dir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	address, stop, err := e.Forward(ctx, namespace, "deployment/auth-gateway", 9901)
	if err != nil {
		diagnosticErr := fmt.Errorf("start Envoy cluster diagnostics port-forward: %w", err)
		writeDiagnostic(dir, "envoy-clusters.json", nil, diagnosticErr)
		fmt.Fprintf(GinkgoWriter, "Envoy cluster state: %v\n", diagnosticErr)
		return
	}
	defer stop()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/clusters?format=json", nil)
	if err != nil {
		diagnosticErr := fmt.Errorf("create Envoy cluster diagnostics request: %w", err)
		writeDiagnostic(dir, "envoy-clusters.json", nil, diagnosticErr)
		fmt.Fprintf(GinkgoWriter, "Envoy cluster state: %v\n", diagnosticErr)
		return
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		diagnosticErr := fmt.Errorf("request Envoy cluster diagnostics: %w", err)
		writeDiagnostic(dir, "envoy-clusters.json", nil, diagnosticErr)
		fmt.Fprintf(GinkgoWriter, "Envoy cluster state: %v\n", diagnosticErr)
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		diagnosticErr := fmt.Errorf("read Envoy cluster diagnostics: %w", err)
		writeDiagnostic(dir, "envoy-clusters.json", nil, diagnosticErr)
		fmt.Fprintf(GinkgoWriter, "Envoy cluster state: %v\n", diagnosticErr)
		return
	}
	writeDiagnostic(dir, "envoy-clusters.json", data, nil)
	fmt.Fprintf(GinkgoWriter, "Envoy cluster state (HTTP %d):\n%s\n", response.StatusCode, data)
	writeEnvoyAdminDiagnostic(ctx, dir, address, "envoy-stats.txt", "/stats?filter=http.ingress")
}
