//go:build e2e

package framework

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

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

type requestContextTransport struct {
	next http.RoundTripper
	ctx  context.Context
}

func (t requestContextTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.next.RoundTrip(request.WithContext(t.ctx))
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

// ForwardWithCleanup registers the port forward for Ginkgo cleanup.
func (e *Environment) ForwardWithCleanup(ctx context.Context, namespace, resource string, remotePort int) string {
	GinkgoHelper()
	address, stop, err := e.Forward(ctx, namespace, resource, remotePort)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(stop)
	return address
}
