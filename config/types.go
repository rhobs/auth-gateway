package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"path"
	"slices"
	"strconv"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

// Config describes gateway behavior, observability, and optional Kubernetes output.
type Config struct {
	Version               int                   `yaml:"version"`
	Node                  EnvoyNode             `yaml:"node,omitempty"`
	Listener              Listener              `yaml:"listener"`
	Overload              *OverloadConfig       `yaml:"overload,omitempty"`
	Authenticators        []Authenticator       `yaml:"authenticators,omitempty"`
	AuthorizationPolicies []AuthorizationPolicy `yaml:"authorization_policies,omitempty"`
	Processing            []Processor           `yaml:"processing,omitempty"`
	Servers               []Server              `yaml:"servers"`
	APIs                  []API                 `yaml:"apis"`
	Observability         ObservabilityConfig   `yaml:"observability,omitempty"`
	Kubernetes            *Kubernetes           `yaml:"kubernetes,omitempty"`
}

// EnvoyNode describes the identity and logical cluster of this Envoy instance.
type EnvoyNode struct {
	ID      string `yaml:"id,omitempty"`
	Cluster string `yaml:"cluster,omitempty"`
}

// Listener describes the socket shared by the configured servers.
type Listener struct {
	Port                          *uint32       `yaml:"port,omitempty"`
	PerConnectionBufferLimitBytes *uint32       `yaml:"per_connection_buffer_limit_bytes,omitempty"`
	MaxRequestHeadersKB           *uint32       `yaml:"max_request_headers_kb,omitempty"`
	MaxRequestHeadersCount        *uint32       `yaml:"max_request_headers_count,omitempty"`
	RequestHeadersTimeout         *Duration     `yaml:"request_headers_timeout,omitempty"`
	RequestTimeout                *Duration     `yaml:"request_timeout,omitempty"`
	ConnectionIdleTimeout         *Duration     `yaml:"connection_idle_timeout,omitempty"`
	StreamIdleTimeout             *Duration     `yaml:"stream_idle_timeout,omitempty"`
	MaxStreamDuration             *Duration     `yaml:"max_stream_duration,omitempty"`
	StreamFlushTimeout            *Duration     `yaml:"stream_flush_timeout,omitempty"`
	TLSHandshakeTimeout           *Duration     `yaml:"tls_handshake_timeout,omitempty"`
	HTTP2                         *HTTP2Options `yaml:"http2,omitempty"`
}

// API describes one upstream and its routes.
type API struct {
	Name            string                `yaml:"name"`
	Routes          []Route               `yaml:"routes"`
	Upstream        Upstream              `yaml:"upstream"`
	Metrics         *APIMetrics           `yaml:"metrics,omitempty"`
	CircuitBreakers *CircuitBreakerConfig `yaml:"circuit_breakers,omitempty"`
	Timeouts        *RouteTimeouts        `yaml:"timeouts,omitempty"`
}

// CircuitBreakerConfig describes Envoy circuit breaker thresholds for an API's upstream cluster.
type CircuitBreakerConfig struct {
	MaxConnections     *uint32 `yaml:"max_connections,omitempty"`
	MaxPendingRequests *uint32 `yaml:"max_pending_requests,omitempty"`
	MaxRequests        *uint32 `yaml:"max_requests,omitempty"`
	MaxRetries         *uint32 `yaml:"max_retries,omitempty"`
}

// Route describes the required methods and path matcher, plus optional rewrite and processing.
type Route struct {
	Methods    []string         `yaml:"methods"`
	Path       PathMatch        `yaml:"path"`
	Rewrite    *PathRewrite     `yaml:"rewrite,omitempty"`
	Processing *RouteProcessing `yaml:"processing,omitempty"`
	Timeouts   *RouteTimeouts   `yaml:"timeouts,omitempty"`
}

// PathMatch selects one exact path, path prefix, or safe regular expression.
type PathMatch struct {
	Exact  string `yaml:"exact,omitempty"`
	Prefix string `yaml:"prefix,omitempty"`
	Regex  string `yaml:"regex,omitempty"`
}

// PathRewrite optionally replaces a path, prefix, or regex match.
type PathRewrite struct {
	Path   string        `yaml:"path,omitempty"`
	Prefix string        `yaml:"prefix,omitempty"`
	Regex  *RegexRewrite `yaml:"regex,omitempty"`
}

// RegexRewrite replaces matches in the request path using RE2 capture groups.
type RegexRewrite struct {
	Pattern      string `yaml:"pattern"`
	Substitution string `yaml:"substitution"`
}

// Upstream describes the service that receives routed requests.
type Upstream struct {
	Address                       string        `yaml:"address"`
	Port                          uint32        `yaml:"port"`
	ConnectTimeout                *Duration     `yaml:"connect_timeout,omitempty"`
	PerConnectionBufferLimitBytes *uint32       `yaml:"per_connection_buffer_limit_bytes,omitempty"`
	HTTPProtocol                  string        `yaml:"http_protocol,omitempty"`
	HTTP2                         *HTTP2Options `yaml:"http2,omitempty"`
	TLSConfig                     *UpstreamTLS  `yaml:"tls_config,omitempty"`
}

// Kubernetes contains the settings needed to generate a Deployment and Service.
type Kubernetes struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	Image     string `yaml:"image"`
	// OTelCollectorImage defaults to the OpenTelemetry Collector Contrib image used by the PoC.
	OTelCollectorImage string                         `yaml:"otel_collector_image,omitempty"`
	Replicas           *int32                         `yaml:"replicas,omitempty"`
	ServicePort        *int32                         `yaml:"service_port,omitempty"`
	HTTPSServicePort   *int32                         `yaml:"https_service_port,omitempty"`
	Resources          KubernetesResourceRequirements `yaml:"resources,omitempty"`
	EnvoyConcurrency   *uint32                        `yaml:"envoy_concurrency,omitempty"`
	Metrics            KubernetesMetrics              `yaml:"metrics,omitempty"`
}

// KubernetesResourceRequirements configures resources for a container.
// Values use Kubernetes resource quantity notation.
type KubernetesResourceRequirements struct {
	Requests map[string]string `yaml:"requests,omitempty"`
	Limits   map[string]string `yaml:"limits,omitempty"`
}

// RouteTimeouts overrides API or listener fallbacks independently for each timer.
type RouteTimeouts struct {
	ResponseTimeout   *Duration `yaml:"response_timeout,omitempty"`
	IdleTimeout       *Duration `yaml:"idle_timeout,omitempty"`
	MaxStreamDuration *Duration `yaml:"max_stream_duration,omitempty"`
}

// HTTP2Options bounds streams and flow-control windows on one HTTP/2 connection.
// Omitted fields retain Envoy's defaults.
type HTTP2Options struct {
	MaxConcurrentStreams        *uint32 `yaml:"max_concurrent_streams,omitempty"`
	InitialStreamWindowSize     *uint32 `yaml:"initial_stream_window_size,omitempty"`
	InitialConnectionWindowSize *uint32 `yaml:"initial_connection_window_size,omitempty"`
}

// UpstreamTLS enables server-authenticated TLS with a DNS or IP verification identity.
type UpstreamTLS struct {
	ServerName string     `yaml:"server_name,omitempty"`
	TrustedCA  *TrustedCA `yaml:"trusted_ca,omitempty"`
}

// OverloadConfig enables process safeguards with explicit capacity budgets.
type OverloadConfig struct {
	MaxHeapBytes             uint64   `yaml:"max_heap_bytes"`
	MaxDownstreamConnections uint32   `yaml:"max_downstream_connections"`
	HeapShrinkThreshold      *float64 `yaml:"heap_shrink_threshold,omitempty"`
	RequestRejectThreshold   *float64 `yaml:"request_reject_threshold,omitempty"`
}

// Authenticator defines one named credential validator.
type Authenticator struct {
	Name       string                     `yaml:"name"`
	JWT        *JWTAuthenticator          `yaml:"jwt,omitempty"`
	APIKey     *APIKeyAuthenticator       `yaml:"api_key,omitempty"`
	Attributes map[string]AttributeSource `yaml:"attributes,omitempty"`
}

// JWTAuthenticator validates one issuer and optionally restricts audiences.
type JWTAuthenticator struct {
	Issuer    string     `yaml:"issuer"`
	JWKS      JWKSConfig `yaml:"jwks"`
	Audiences []string   `yaml:"audiences,omitempty"`
}

// AttributeSource selects one original value from a verified claim, key credential, or request header.
type AttributeSource struct {
	ClaimPath  []string `yaml:"claim_path,omitempty"`
	Header     *string  `yaml:"header,omitempty"`
	Credential *bool    `yaml:"credential,omitempty"`
}

// APIKeyAuthenticator reads keys from an ECDS file.
type APIKeyAuthenticator struct {
	Secret string `yaml:"secret,omitempty"`
	Header string `yaml:"header,omitempty"`
}

// Processor transforms working attributes after JWT verification.
type Processor struct {
	Name       string                       `yaml:"name"`
	Type       string                       `yaml:"type"`
	Attributes map[string]AttributeMappings `yaml:"attributes,omitempty"`
}

// AttributeMappings defines exact string lookups for one working attribute.
type AttributeMappings struct {
	Mappings map[string]string `yaml:"mappings,omitempty"`
}

// AuthorizationPolicy contains allow grants for named APIs.
type AuthorizationPolicy struct {
	Name   string               `yaml:"name"`
	Grants []AuthorizationGrant `yaml:"grants,omitempty"`
}

// AuthorizationGrant allows selected APIs for raw verified claims from one authenticator.
type AuthorizationGrant struct {
	Authenticator string              `yaml:"authenticator"`
	APIs          []string            `yaml:"apis"`
	Attributes    map[string][]string `yaml:"attributes"`
}

// Authentication selects credential validators for a server.
type Authentication struct {
	AnyOf []string `yaml:"any_of,omitempty"`
	AllOf []string `yaml:"all_of,omitempty"`
}

// Authorization selects policies for a server.
type Authorization struct {
	AnyOf []string `yaml:"any_of,omitempty"`
	AllOf []string `yaml:"all_of,omitempty"`
}

// RouteProcessing describes optional per-route request processing.
type RouteProcessing struct {
	RequestHeaders []RequestHeaderMapping `yaml:"request_headers,omitempty"`
}

// RequestHeaderMapping sets an upstream header from a processed attribute.
type RequestHeaderMapping struct {
	Name          string `yaml:"name"`
	FromAttribute string `yaml:"from_attribute"`
}

// JWKSConfig controls on-demand key fetching for one JWT authenticator.
type JWKSConfig struct {
	URI             string                `yaml:"uri"`
	CacheDuration   *Duration             `yaml:"cache_duration,omitempty"`
	FetchTimeout    *Duration             `yaml:"fetch_timeout,omitempty"`
	ConnectTimeout  *Duration             `yaml:"connect_timeout,omitempty"`
	TrustedCA       *TrustedCA            `yaml:"trusted_ca,omitempty"`
	CircuitBreakers *CircuitBreakerConfig `yaml:"circuit_breakers,omitempty"`
}

// TrustedCA selects a replacement trust bundle. Omission uses the system bundle.
type TrustedCA struct {
	Filename  string       `yaml:"filename,omitempty"`
	ConfigMap *CAConfigMap `yaml:"config_map,omitempty"`
}

// CAConfigMap references one key of an existing ConfigMap in the gateway namespace.
type CAConfigMap struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

// Server binds an exact hostname and protocol to named APIs and optional access policies.
type Server struct {
	Hostname       string          `yaml:"hostname"`
	TLSConfig      *ServerTLS      `yaml:"tls_config,omitempty"`
	Authentication *Authentication `yaml:"authentication,omitempty"`
	Authorization  *Authorization  `yaml:"authorization,omitempty"`
	APIs           []string        `yaml:"apis,omitempty"`
}

// ServerTLS describes the certificate used by one HTTPS server.
type ServerTLS struct {
	Secret      string `yaml:"secret,omitempty"`
	Certificate string `yaml:"certificate,omitempty"`
	PrivateKey  string `yaml:"private_key,omitempty"`
}

// APIKeyCredential binds an opaque key to verified string attributes.
type APIKeyCredential struct {
	Key        string            `yaml:"key"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
}

// KubernetesResources contains native objects generated for a gateway.
type KubernetesResources struct {
	ConfigMap              corev1.ConfigMap
	ProcessingConfigMap    *corev1.ConfigMap
	OTelCollectorConfigMap *corev1.ConfigMap
	ServiceAccount         corev1.ServiceAccount
	Deployment             appsv1.Deployment
	Service                corev1.Service
}

// Duration is a Go duration encoded as a YAML string, such as 250ms or 5s.
// Zero is accepted only by settings that explicitly allow it.
type Duration time.Duration

type cloneable[T any] interface {
	clone() T
}

func cloneSlice[T cloneable[T]](values []T) []T {
	if values == nil {
		return nil
	}
	cloned := make([]T, len(values))
	for index, value := range values {
		cloned[index] = value.clone()
	}
	return cloned
}

func cloneConfigPointer[T cloneable[T]](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := (*value).clone()
	return &cloned
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (c Config) clone() Config {
	c.Listener = c.Listener.clone()
	c.Overload = cloneConfigPointer(c.Overload)
	c.Authenticators = cloneSlice(c.Authenticators)
	c.AuthorizationPolicies = cloneSlice(c.AuthorizationPolicies)
	c.Processing = cloneSlice(c.Processing)
	c.Servers = cloneSlice(c.Servers)
	c.APIs = cloneSlice(c.APIs)
	c.Observability = c.Observability.clone()
	c.Kubernetes = cloneConfigPointer(c.Kubernetes)
	return c
}

func (l Listener) clone() Listener {
	l.Port = clonePointer(l.Port)
	l.PerConnectionBufferLimitBytes = clonePointer(l.PerConnectionBufferLimitBytes)
	l.MaxRequestHeadersKB = clonePointer(l.MaxRequestHeadersKB)
	l.MaxRequestHeadersCount = clonePointer(l.MaxRequestHeadersCount)
	l.RequestHeadersTimeout = clonePointer(l.RequestHeadersTimeout)
	l.RequestTimeout = clonePointer(l.RequestTimeout)
	l.ConnectionIdleTimeout = clonePointer(l.ConnectionIdleTimeout)
	l.StreamIdleTimeout = clonePointer(l.StreamIdleTimeout)
	l.MaxStreamDuration = clonePointer(l.MaxStreamDuration)
	l.StreamFlushTimeout = clonePointer(l.StreamFlushTimeout)
	l.TLSHandshakeTimeout = clonePointer(l.TLSHandshakeTimeout)
	l.HTTP2 = cloneConfigPointer(l.HTTP2)
	return l
}

func (a API) clone() API {
	a.Routes = cloneSlice(a.Routes)
	a.Upstream = a.Upstream.clone()
	a.Metrics = cloneConfigPointer(a.Metrics)
	if a.CircuitBreakers != nil {
		circuitBreakers := a.CircuitBreakers.clone()
		a.CircuitBreakers = &circuitBreakers
	}
	a.Timeouts = cloneConfigPointer(a.Timeouts)
	return a
}

func (c *CircuitBreakerConfig) clone() CircuitBreakerConfig {
	cloned := *c
	cloned.MaxConnections = clonePointer(c.MaxConnections)
	cloned.MaxPendingRequests = clonePointer(c.MaxPendingRequests)
	cloned.MaxRequests = clonePointer(c.MaxRequests)
	cloned.MaxRetries = clonePointer(c.MaxRetries)
	return cloned
}

func (r Route) clone() Route {
	r.Methods = slices.Clone(r.Methods)
	r.Rewrite = cloneConfigPointer(r.Rewrite)
	r.Processing = cloneConfigPointer(r.Processing)
	r.Timeouts = cloneConfigPointer(r.Timeouts)
	return r
}

func (r PathRewrite) clone() PathRewrite {
	r.Regex = cloneConfigPointer(r.Regex)
	return r
}

func (r RegexRewrite) clone() RegexRewrite {
	return r
}

func (u Upstream) clone() Upstream {
	u.ConnectTimeout = clonePointer(u.ConnectTimeout)
	u.PerConnectionBufferLimitBytes = clonePointer(u.PerConnectionBufferLimitBytes)
	u.HTTP2 = cloneConfigPointer(u.HTTP2)
	u.TLSConfig = cloneConfigPointer(u.TLSConfig)
	return u
}

func (k Kubernetes) clone() Kubernetes {
	k.Replicas = clonePointer(k.Replicas)
	k.ServicePort = clonePointer(k.ServicePort)
	k.HTTPSServicePort = clonePointer(k.HTTPSServicePort)
	k.Resources = k.Resources.clone()
	k.EnvoyConcurrency = clonePointer(k.EnvoyConcurrency)
	k.Metrics = k.Metrics.clone()
	return k
}

func (r KubernetesResourceRequirements) clone() KubernetesResourceRequirements {
	r.Requests = maps.Clone(r.Requests)
	r.Limits = maps.Clone(r.Limits)
	return r
}

func (t RouteTimeouts) clone() RouteTimeouts {
	t.ResponseTimeout = clonePointer(t.ResponseTimeout)
	t.IdleTimeout = clonePointer(t.IdleTimeout)
	t.MaxStreamDuration = clonePointer(t.MaxStreamDuration)
	return t
}

func (h HTTP2Options) clone() HTTP2Options {
	h.MaxConcurrentStreams = clonePointer(h.MaxConcurrentStreams)
	h.InitialStreamWindowSize = clonePointer(h.InitialStreamWindowSize)
	h.InitialConnectionWindowSize = clonePointer(h.InitialConnectionWindowSize)
	return h
}

func (t UpstreamTLS) clone() UpstreamTLS {
	t.TrustedCA = cloneConfigPointer(t.TrustedCA)
	return t
}

func (o OverloadConfig) clone() OverloadConfig {
	o.HeapShrinkThreshold = clonePointer(o.HeapShrinkThreshold)
	o.RequestRejectThreshold = clonePointer(o.RequestRejectThreshold)
	return o
}

func (a Authenticator) clone() Authenticator {
	if a.Attributes != nil {
		attributes := make(map[string]AttributeSource, len(a.Attributes))
		for name, source := range a.Attributes {
			attributes[name] = source.clone()
		}
		a.Attributes = attributes
	}
	a.JWT = cloneConfigPointer(a.JWT)
	a.APIKey = clonePointer(a.APIKey)
	return a
}

func (j JWTAuthenticator) clone() JWTAuthenticator {
	j.JWKS = j.JWKS.clone()
	j.Audiences = slices.Clone(j.Audiences)
	return j
}

func (a AttributeSource) clone() AttributeSource {
	a.ClaimPath = slices.Clone(a.ClaimPath)
	a.Header = clonePointer(a.Header)
	a.Credential = clonePointer(a.Credential)
	return a
}

func (p Processor) clone() Processor {
	if p.Attributes != nil {
		attributes := make(map[string]AttributeMappings, len(p.Attributes))
		for name, attribute := range p.Attributes {
			attributes[name] = attribute.clone()
		}
		p.Attributes = attributes
	}
	return p
}

func (a AttributeMappings) clone() AttributeMappings {
	a.Mappings = maps.Clone(a.Mappings)
	return a
}

func (p AuthorizationPolicy) clone() AuthorizationPolicy {
	p.Grants = cloneSlice(p.Grants)
	return p
}

func (g AuthorizationGrant) clone() AuthorizationGrant {
	g.APIs = slices.Clone(g.APIs)
	if g.Attributes != nil {
		attributes := make(map[string][]string, len(g.Attributes))
		for name, allowed := range g.Attributes {
			attributes[name] = slices.Clone(allowed)
		}
		g.Attributes = attributes
	}
	return g
}

func (a Authentication) clone() Authentication {
	a.AnyOf = slices.Clone(a.AnyOf)
	a.AllOf = slices.Clone(a.AllOf)
	return a
}

func (a Authorization) clone() Authorization {
	a.AnyOf = slices.Clone(a.AnyOf)
	a.AllOf = slices.Clone(a.AllOf)
	return a
}

func (p RouteProcessing) clone() RouteProcessing {
	p.RequestHeaders = slices.Clone(p.RequestHeaders)
	return p
}

func (j JWKSConfig) clone() JWKSConfig {
	j.CacheDuration = clonePointer(j.CacheDuration)
	j.FetchTimeout = clonePointer(j.FetchTimeout)
	j.ConnectTimeout = clonePointer(j.ConnectTimeout)
	j.TrustedCA = cloneConfigPointer(j.TrustedCA)
	if j.CircuitBreakers != nil {
		circuitBreakers := j.CircuitBreakers.clone()
		j.CircuitBreakers = &circuitBreakers
	}
	return j
}

func (ca TrustedCA) clone() TrustedCA {
	ca.ConfigMap = clonePointer(ca.ConfigMap)
	return ca
}

func (s Server) clone() Server {
	s.TLSConfig = cloneConfigPointer(s.TLSConfig)
	s.Authentication = cloneConfigPointer(s.Authentication)
	s.Authorization = cloneConfigPointer(s.Authorization)
	s.APIs = slices.Clone(s.APIs)
	return s
}

func (s ServerTLS) clone() ServerTLS {
	return s
}

func (c APIKeyCredential) clone() APIKeyCredential {
	c.Attributes = maps.Clone(c.Attributes)
	return c
}

func (a Authenticator) providesAttribute(name string) bool {
	_, exists := a.Attributes[name]
	return exists
}

func (a Authenticator) credentialAttributeNames() []string {
	var names []string
	for name, source := range a.Attributes {
		if source.Credential != nil && *source.Credential {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (j JWKSConfig) validate(name string, kubernetes bool) error {
	for _, setting := range []struct {
		name  string
		value *Duration
	}{
		{"cache_duration", j.CacheDuration}, {"fetch_timeout", j.FetchTimeout}, {"connect_timeout", j.ConnectTimeout},
	} {
		if err := validateDuration(name+"."+setting.name, setting.value, false); err != nil {
			return err
		}
	}
	if *j.ConnectTimeout > *j.FetchTimeout {
		return fmt.Errorf("%s.connect_timeout (%s) must not exceed %s.fetch_timeout (%s)", name, j.ConnectTimeout, name, j.FetchTimeout)
	}
	return validateTrustedCA(name+".trusted_ca", j.TrustedCA, kubernetes)
}

func (ref CAConfigMap) id() string {
	digest := sha256.Sum256([]byte(ref.Name + "\x00" + ref.Key))
	return hex.EncodeToString(digest[:16])
}

func (ca TrustedCA) filename() string {
	if ca.ConfigMap != nil {
		return path.Join(caDirectory, ca.ConfigMap.id(), caCertificateFilename)
	}
	return ca.Filename
}

// Objects returns the resources in apply order.
func (r *KubernetesResources) Objects() []runtime.Object {
	objects := []runtime.Object{&r.ConfigMap}
	if r.ProcessingConfigMap != nil {
		objects = append(objects, r.ProcessingConfigMap)
	}
	if r.OTelCollectorConfigMap != nil {
		objects = append(objects, r.OTelCollectorConfigMap)
	}
	return append(objects, &r.ServiceAccount, &r.Deployment, &r.Service)
}

// YAML serializes all resources as a Kubernetes manifest stream.
func (r *KubernetesResources) YAML() ([]byte, error) {
	serializer := kjson.NewSerializerWithOptions(kjson.DefaultMetaFactory, nil, nil, kjson.SerializerOptions{Yaml: true})
	var output bytes.Buffer
	for index, object := range r.Objects() {
		if index > 0 {
			output.WriteString("---\n")
		}
		if err := serializer.Encode(object, &output); err != nil {
			return nil, fmt.Errorf("encode Kubernetes %T: %w", object, err)
		}
	}
	return output.Bytes(), nil
}

func (d *Duration) String() string { return time.Duration(*d).String() }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Value == "" {
		return &durationYAMLError{line: node.Line, column: node.Column, err: fmt.Errorf("must be a duration string with units, such as 250ms or 5s")}
	}
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return &durationYAMLError{line: node.Line, column: node.Column, err: fmt.Errorf("invalid duration %q: %w", node.Value, err)}
	}
	if err := validateDurationValue(Duration(value), true); err != nil {
		return &durationYAMLError{line: node.Line, column: node.Column, err: err}
	}
	*d = Duration(value)
	return nil
}

func (d *Duration) MarshalYAML() (any, error) {
	if err := validateDurationValue(*d, true); err != nil {
		return nil, err
	}
	return d.String(), nil
}

func (d *Duration) protobuf() *durationpb.Duration { return durationpb.New(time.Duration(*d)) }

func (l Listener) validate(metricsEnabled, tracingEnabled bool) error {
	if *l.Port == 0 || *l.Port > 65535 {
		return fmt.Errorf("listener.port must be between 1 and 65535")
	}
	if err := validateObservabilityListenerPort(l.Port, metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	for _, value := range []struct {
		name  string
		value *uint32
		max   uint32
	}{
		{"per_connection_buffer_limit_bytes", l.PerConnectionBufferLimitBytes, ^uint32(0)},
		{"max_request_headers_kb", l.MaxRequestHeadersKB, 8192},
		{"max_request_headers_count", l.MaxRequestHeadersCount, ^uint32(0)},
	} {
		if *value.value == 0 || *value.value > value.max {
			return fmt.Errorf("listener.%s must be between 1 and %d", value.name, value.max)
		}
	}
	for _, value := range []struct {
		name  string
		value *Duration
	}{
		{"request_headers_timeout", l.RequestHeadersTimeout}, {"request_timeout", l.RequestTimeout},
		{"connection_idle_timeout", l.ConnectionIdleTimeout}, {"stream_idle_timeout", l.StreamIdleTimeout},
		{maxStreamDurationFieldName, l.MaxStreamDuration}, {"stream_flush_timeout", l.StreamFlushTimeout},
		{"tls_handshake_timeout", l.TLSHandshakeTimeout},
	} {
		if err := validateDuration("listener."+value.name, value.value, false); err != nil {
			return err
		}
	}
	if *l.RequestHeadersTimeout > *l.RequestTimeout {
		return fmt.Errorf("listener.request_headers_timeout (%s) must not exceed listener.request_timeout (%s)", l.RequestHeadersTimeout, l.RequestTimeout)
	}
	if l.HTTP2 != nil {
		return l.HTTP2.validate("listener.http2")
	}
	return nil
}

func (u Upstream) validate(name string, kubernetes bool) error {
	if err := validateDuration(name+".connect_timeout", u.ConnectTimeout, false); err != nil {
		return err
	}
	if *u.PerConnectionBufferLimitBytes == 0 {
		return fmt.Errorf("%s.per_connection_buffer_limit_bytes must be positive", name)
	}
	if u.HTTPProtocol != http1Protocol && u.HTTPProtocol != http2Protocol {
		return fmt.Errorf("%s.http_protocol must be http1 or http2", name)
	}
	if u.HTTP2 != nil && u.HTTPProtocol != http2Protocol {
		return fmt.Errorf("%s.http2 requires http_protocol: http2", name)
	}
	if u.HTTP2 != nil {
		if err := u.HTTP2.validate(name + ".http2"); err != nil {
			return err
		}
	}
	if u.TLSConfig != nil {
		if u.TLSConfig.ServerName != "" && !validDNSHost(u.TLSConfig.ServerName) {
			return fmt.Errorf("%s.tls_config.server_name must be an exact DNS hostname", name)
		}
		return validateTrustedCA(name+".tls_config.trusted_ca", u.TLSConfig.TrustedCA, kubernetes)
	}
	return nil
}

func (h HTTP2Options) validate(name string) error {
	for _, value := range []struct {
		name  string
		value *uint32
		min   uint32
	}{
		{"max_concurrent_streams", h.MaxConcurrentStreams, 1},
		{"initial_stream_window_size", h.InitialStreamWindowSize, 65535},
		{"initial_connection_window_size", h.InitialConnectionWindowSize, 65535},
	} {
		if value.value != nil && (*value.value < value.min || *value.value > 2147483647) {
			return fmt.Errorf("%s.%s must be between %d and 2147483647", name, value.name, value.min)
		}
	}
	if err := h.envoy().ValidateAll(); err != nil {
		return fmt.Errorf(fieldWrapErrorFormat, name, err)
	}
	return nil
}

func (h HTTP2Options) envoy() *core.Http2ProtocolOptions {
	return &core.Http2ProtocolOptions{
		MaxConcurrentStreams:        optionalUint32(h.MaxConcurrentStreams),
		InitialStreamWindowSize:     optionalUint32(h.InitialStreamWindowSize),
		InitialConnectionWindowSize: optionalUint32(h.InitialConnectionWindowSize),
	}
}

func (o OverloadConfig) validate(k *Kubernetes) error {
	if o.MaxHeapBytes == 0 {
		return fmt.Errorf("overload.max_heap_bytes must be positive")
	}
	if o.MaxDownstreamConnections == 0 {
		return fmt.Errorf("overload.max_downstream_connections must be positive")
	}
	for _, field := range []struct {
		name  string
		value float64
	}{{"heap_shrink_threshold", *o.HeapShrinkThreshold}, {"request_reject_threshold", *o.RequestRejectThreshold}} {
		if math.IsNaN(field.value) || math.IsInf(field.value, 0) || field.value <= 0 || field.value >= 1 {
			return fmt.Errorf("overload.%s must be finite and between 0 and 1 (exclusive)", field.name)
		}
	}
	if *o.HeapShrinkThreshold >= *o.RequestRejectThreshold {
		return fmt.Errorf("overload.heap_shrink_threshold must be less than overload.request_reject_threshold")
	}
	if k != nil {
		limit, err := resource.ParseQuantity(k.Resources.Limits[kubernetesMemoryResourceName])
		if err != nil || limit.Sign() <= 0 {
			return fmt.Errorf("overload requires a positive kubernetes.resources.limits.memory")
		}
		// Decimal quantities preserve the full uint64 budget without an int64 cast.
		heapSize := resource.MustParse(strconv.FormatUint(o.MaxHeapBytes, 10))
		if heapSize.Cmp(limit) >= 0 {
			return fmt.Errorf("overload.max_heap_bytes (%d) must be less than kubernetes.resources.limits.memory (%s)", o.MaxHeapBytes, limit.String())
		}
	}
	return nil
}
