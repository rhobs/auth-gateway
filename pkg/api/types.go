package api

// AdmissionControlConfig optionally sheds requests based on one API's success rate.
type AdmissionControlConfig struct {
	Enabled                 bool      `yaml:"enabled,omitempty"`
	SamplingWindow          *Duration `yaml:"sampling_window,omitempty"`
	SrThreshold             *float64  `yaml:"sr_threshold,omitempty"`
	RPSThreshold            *uint32   `yaml:"rps_threshold,omitempty"`
	MaxRejectionProbability *float64  `yaml:"max_rejection_probability,omitempty"`
}

// API describes one upstream and its routes.
type API struct {
	Name             string                  `yaml:"name"`
	Routes           []Route                 `yaml:"routes"`
	Upstream         Upstream                `yaml:"upstream"`
	Metrics          *APIMetrics             `yaml:"metrics,omitempty"`
	AdmissionControl *AdmissionControlConfig `yaml:"admission_control,omitempty"`
	FaultInjection   *FaultInjectionConfig   `yaml:"fault_injection,omitempty"`
	CircuitBreakers  *CircuitBreakerConfig   `yaml:"circuit_breakers,omitempty"`
	Timeouts         *RouteTimeouts          `yaml:"timeouts,omitempty"`
}

// APIKeyAuthenticator reads keys from an ECDS file.
type APIKeyAuthenticator struct {
	Secret string `yaml:"secret,omitempty"`
	Header string `yaml:"header,omitempty"`
}

// APIKeyCredential binds an opaque key to verified string attributes.
type APIKeyCredential struct {
	Key        string            `yaml:"key"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
}

// AttributeSource selects one original value from a verified credential or request header.
type AttributeSource struct {
	Name       string         `yaml:"name"`
	FromSource string         `yaml:"from_source"`
	Value      AttributeValue `yaml:"value"`
}

// Authenticator defines one named credential validator.
type Authenticator struct {
	Name       string               `yaml:"name"`
	JWT        *JWTAuthenticator    `yaml:"jwt,omitempty"`
	APIKey     *APIKeyAuthenticator `yaml:"api_key,omitempty"`
	MTLS       *MTLSAuthenticator   `yaml:"mtls,omitempty"`
	Attributes []AttributeSource    `yaml:"attributes,omitempty"`
}

// Authentication selects one credential type for an access entry.
type Authentication struct {
	JWT    *JWTAuthentication      `yaml:"jwt,omitempty"`
	APIKey *AuthenticatorReference `yaml:"api_key,omitempty"`
}

// JWTAuthentication selects the issuers trusted by one access entry.
type JWTAuthentication struct {
	Providers []string `yaml:"providers"`
}

// AuthenticatorReference selects one named credential validator.
type AuthenticatorReference struct {
	Authenticator string `yaml:"authenticator"`
}

// AuthorizationGrant checks attributes supplied by its verifying authenticator.
type AuthorizationGrant struct {
	Authenticator string            `yaml:"authenticator"`
	Attributes    []MatchExpression `yaml:"attributes"`
}

// Authorization grants access within one server/API entry.
type Authorization struct {
	Grants   []AuthorizationGrant   `yaml:"grants,omitempty"`
	ExtAuthz *ExternalAuthorization `yaml:"ext_authz,omitempty"`
}

// ExternalAuthorization selects a service for an access entry.
type ExternalAuthorization struct {
	Service string `yaml:"service"`
}

// ExternalAuthorizationService describes a gRPC authorization service.
type ExternalAuthorizationService struct {
	Name              string            `yaml:"name"`
	Upstream          Upstream          `yaml:"upstream"`
	Timeout           *Duration         `yaml:"timeout,omitempty"`
	RequestHeaders    []string          `yaml:"request_headers"`
	CredentialHeaders []string          `yaml:"credential_headers,omitempty"`
	Attributes        []AttributeSource `yaml:"attributes,omitempty"`
}

// APIBinding exposes one API with explicit public access or protected entries.
type APIBinding struct {
	Name   string   `yaml:"name"`
	Public bool     `yaml:"public,omitempty"`
	Access []Access `yaml:"access,omitempty"`
}

// Access binds request selectors to one authentication and authorization path.
type Access struct {
	Tenant         string          `yaml:"tenant,omitempty"`
	Name           string          `yaml:"name,omitempty"`
	Match          AccessMatch     `yaml:"match,omitempty"`
	Authentication *Authentication `yaml:"authentication,omitempty"`
	Authorization  Authorization   `yaml:"authorization"`
}

// AccessMatch requires every configured request header to match.
type AccessMatch struct {
	Headers []MatchExpression `yaml:"headers,omitempty"`
}

// Config describes gateway behavior, observability, and optional Kubernetes output.
type Config struct {
	Version          int                            `yaml:"version"`
	Node             EnvoyNode                      `yaml:"node,omitempty"`
	Listener         Listener                       `yaml:"listener"`
	Overload         *OverloadConfig                `yaml:"overload,omitempty"`
	Authenticators   []Authenticator                `yaml:"authenticators,omitempty"`
	ExtAuthzServices []ExternalAuthorizationService `yaml:"ext_authz_services,omitempty"`
	Servers          []Server                       `yaml:"servers"`
	APIs             []API                          `yaml:"apis"`
	Observability    ObservabilityConfig            `yaml:"observability,omitempty"`
	Kubernetes       *Kubernetes                    `yaml:"kubernetes,omitempty"`
}

// EnvoyNode describes the identity and logical cluster of this Envoy instance.
type EnvoyNode struct {
	ID      string `yaml:"id,omitempty"`
	Cluster string `yaml:"cluster,omitempty"`
}

// FaultInjectionConfig optionally aborts requests to one API with HTTP errors.
type FaultInjectionConfig struct {
	Enabled bool              `yaml:"enabled,omitempty"`
	Abort   *FaultAbortConfig `yaml:"abort,omitempty"`
	Match   *FaultMatchConfig `yaml:"match,omitempty"`
}

// FaultMatchConfig limits faults to exact headers and authenticated attributes.
type FaultMatchConfig struct {
	Headers    map[string]string   `yaml:"headers,omitempty"`
	Attributes map[string][]string `yaml:"attributes,omitempty"`
}

// FaultAbortConfig sets the status and whole-number percentage of injected errors.
type FaultAbortConfig struct {
	HTTPStatus uint32 `yaml:"http_status"`
	Percentage uint32 `yaml:"percentage"`
}

// HTTP2Options bounds streams and flow-control windows on one HTTP/2 connection.
// Omitted fields retain Envoy's defaults.
type HTTP2Options struct {
	MaxConcurrentStreams        *uint32 `yaml:"max_concurrent_streams,omitempty"`
	InitialStreamWindowSize     *uint32 `yaml:"initial_stream_window_size,omitempty"`
	InitialConnectionWindowSize *uint32 `yaml:"initial_connection_window_size,omitempty"`
}

// JWTAuthenticator validates one issuer and optionally restricts audiences.
type JWTAuthenticator struct {
	Issuer    string     `yaml:"issuer"`
	JWKS      JWKSConfig `yaml:"jwks"`
	Audiences []string   `yaml:"audiences,omitempty"`
}

// JWKSConfig controls on-demand key fetching for one JWT authenticator.
type JWKSConfig struct {
	URI             string                `yaml:"uri"`
	DNSLookupFamily string                `yaml:"dns_lookup_family,omitempty"`
	CacheDuration   *Duration             `yaml:"cache_duration,omitempty"`
	FetchTimeout    *Duration             `yaml:"fetch_timeout,omitempty"`
	ConnectTimeout  *Duration             `yaml:"connect_timeout,omitempty"`
	TrustedCA       *TrustedCA            `yaml:"trusted_ca,omitempty"`
	CircuitBreakers *CircuitBreakerConfig `yaml:"circuit_breakers,omitempty"`
}

// KubernetesMetrics configures resources for the collector container.
type KubernetesMetrics struct {
	Resources KubernetesResourceRequirements `yaml:"resources,omitempty"`
}

// Kubernetes contains the settings needed to generate a Deployment and Service.
type Kubernetes struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	// Image overrides the default Envoy image for generated Deployments.
	Image string `yaml:"image"`
	// OTelCollectorImage overrides the default OpenTelemetry Collector sidecar image.
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

// APIMetrics enables one request counter and optionally binds labels to working attributes.
type APIMetrics struct {
	Labels map[string]string `yaml:"labels,omitempty"`
}

// MTLSAuthenticator validates client certificates against an explicit CA bundle.
type MTLSAuthenticator struct {
	TrustedCA *TrustedCA `yaml:"trusted_ca"`
}

// ObservabilityConfig groups gateway-wide telemetry settings.
type ObservabilityConfig struct {
	Metrics ObservabilityMetrics `yaml:"metrics,omitempty"`
	Tracing ObservabilityTracing `yaml:"tracing,omitempty"`
}

// ObservabilityMetrics configures the scraping, exposure, and naming of Envoy metrics.
type ObservabilityMetrics struct {
	Enabled          *bool     `yaml:"enabled,omitempty"`
	ScrapeInterval   *Duration `yaml:"scrape_interval,omitempty"`
	ScrapeTimeout    *Duration `yaml:"scrape_timeout,omitempty"`
	CustomMetricName *string   `yaml:"custom_metric_name,omitempty"`
}

// ObservabilityTracing configures Envoy tracing and the collector's OTLP exporter.
type ObservabilityTracing struct {
	Enabled            *bool    `yaml:"enabled,omitempty"`
	Endpoint           string   `yaml:"endpoint,omitempty"`
	ServiceName        string   `yaml:"service_name,omitempty"`
	SamplingPercentage *float64 `yaml:"sampling_percentage,omitempty"`
	Insecure           *bool    `yaml:"insecure,omitempty"`
}

// OverloadConfig enables process safeguards with explicit capacity budgets.
type OverloadConfig struct {
	MaxHeapBytes             uint64   `yaml:"max_heap_bytes"`
	MaxDownstreamConnections uint32   `yaml:"max_downstream_connections"`
	HeapShrinkThreshold      *float64 `yaml:"heap_shrink_threshold,omitempty"`
	RequestRejectThreshold   *float64 `yaml:"request_reject_threshold,omitempty"`
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

// RouteProcessing describes optional per-route request processing.
type RouteProcessing struct {
	RequestHeaders []RequestHeaderMapping `yaml:"request_headers,omitempty"`
}

// RequestHeaderMapping sets an upstream header from a processed attribute.
type RequestHeaderMapping struct {
	Name          string `yaml:"name"`
	FromAttribute string `yaml:"from_attribute"`
}

// Server binds an exact hostname and protocol to API access rules.
type Server struct {
	Hostname  string       `yaml:"hostname"`
	TLSConfig *ServerTLS   `yaml:"tls_config,omitempty"`
	APIs      []APIBinding `yaml:"apis"`
}

// ServerTLS describes the certificate used by one HTTPS server.
type ServerTLS struct {
	Secret      string                  `yaml:"secret,omitempty"`
	Certificate string                  `yaml:"certificate,omitempty"`
	PrivateKey  string                  `yaml:"private_key,omitempty"`
	MTLS        *AuthenticatorReference `yaml:"mtls,omitempty"`
}

// RouteTimeouts overrides API or listener fallbacks independently for each timer.
type RouteTimeouts struct {
	ResponseTimeout   *Duration `yaml:"response_timeout,omitempty"`
	IdleTimeout       *Duration `yaml:"idle_timeout,omitempty"`
	MaxStreamDuration *Duration `yaml:"max_stream_duration,omitempty"`
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

// CircuitBreakerConfig describes Envoy circuit breaker thresholds for an upstream cluster.
type CircuitBreakerConfig struct {
	MaxConnections     *uint32 `yaml:"max_connections,omitempty"`
	MaxPendingRequests *uint32 `yaml:"max_pending_requests,omitempty"`
	MaxRequests        *uint32 `yaml:"max_requests,omitempty"`
	MaxRetries         *uint32 `yaml:"max_retries,omitempty"`
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

// UpstreamTLS enables server-authenticated TLS with a DNS or IP verification identity.
type UpstreamTLS struct {
	ServerName string     `yaml:"server_name,omitempty"`
	TrustedCA  *TrustedCA `yaml:"trusted_ca,omitempty"`
}
