// Package config preserves the original import path while callers migrate to pkg/config, pkg/api, and pkg/envoy.
package config

import (
	"github.com/rhobs/auth-gateway/pkg/api"
	gatewayconfig "github.com/rhobs/auth-gateway/pkg/config"
	"github.com/rhobs/auth-gateway/pkg/envoy"
	"github.com/rhobs/auth-gateway/pkg/kubernetes"
	"github.com/rhobs/auth-gateway/pkg/otel"
	"io"
	corev1 "k8s.io/api/core/v1"
	"time"
)

type (
	AdmissionControlConfig         = api.AdmissionControlConfig
	API                            = api.API
	APIKeyAuthenticator            = api.APIKeyAuthenticator
	APIKeyCredential               = api.APIKeyCredential
	AttributeSource                = api.AttributeSource
	Authenticator                  = api.Authenticator
	Authentication                 = api.Authentication
	AuthorizationPolicy            = api.AuthorizationPolicy
	AuthorizationGrant             = api.AuthorizationGrant
	Authorization                  = api.Authorization
	Config                         = api.Config
	EnvoyNode                      = api.EnvoyNode
	FaultInjectionConfig           = api.FaultInjectionConfig
	FaultMatchConfig               = api.FaultMatchConfig
	FaultAbortConfig               = api.FaultAbortConfig
	HTTP2Options                   = api.HTTP2Options
	JWTAuthenticator               = api.JWTAuthenticator
	JWKSConfig                     = api.JWKSConfig
	KubernetesMetrics              = api.KubernetesMetrics
	Kubernetes                     = api.Kubernetes
	KubernetesResourceRequirements = api.KubernetesResourceRequirements
	Listener                       = api.Listener
	APIMetrics                     = api.APIMetrics
	MTLSAuthenticator              = api.MTLSAuthenticator
	ObservabilityConfig            = api.ObservabilityConfig
	ObservabilityMetrics           = api.ObservabilityMetrics
	ObservabilityTracing           = api.ObservabilityTracing
	OverloadConfig                 = api.OverloadConfig
	Route                          = api.Route
	PathMatch                      = api.PathMatch
	PathRewrite                    = api.PathRewrite
	RegexRewrite                   = api.RegexRewrite
	RouteProcessing                = api.RouteProcessing
	RequestHeaderMapping           = api.RequestHeaderMapping
	Server                         = api.Server
	ServerTLS                      = api.ServerTLS
	RouteTimeouts                  = api.RouteTimeouts
	TrustedCA                      = api.TrustedCA
	CAConfigMap                    = api.CAConfigMap
	CircuitBreakerConfig           = api.CircuitBreakerConfig
	Upstream                       = api.Upstream
	UpstreamTLS                    = api.UpstreamTLS
	Duration                       = api.Duration
	GeneratedFile                  = envoy.GeneratedFile
	GeneratedFiles                 = envoy.GeneratedFiles
	KubernetesResources            = kubernetes.Resources
)

const (
	DefaultEnvoyImage         = gatewayconfig.DefaultEnvoyImage
	DefaultOTelCollectorImage = gatewayconfig.DefaultOTelCollectorImage
	EnvoyConfigDirectory      = gatewayconfig.EnvoyConfigDirectory
	APIKeyConfigDirectory     = gatewayconfig.APIKeyConfigDirectory
	TrustedCADirectory        = gatewayconfig.TrustedCADirectory
	EnvoyBootstrapPath        = gatewayconfig.EnvoyBootstrapPath
	APIKeyECDSPath            = gatewayconfig.APIKeyECDSPath
)

func Load(r io.Reader) (api.Config, error)                { return gatewayconfig.Load(r) }
func Validate(c api.Config) error                         { return gatewayconfig.Validate(c) }
func NewDuration(v time.Duration) *api.Duration           { return api.NewDuration(v) }
func Generate(c api.Config) (envoy.GeneratedFiles, error) { return envoy.Generate(c) }
func GenerateKubernetes(c api.Config) (*kubernetes.Resources, error) {
	return kubernetes.Generate(c)
}
func GenerateOTelCollectorConfig(c api.Config) ([]byte, error) {
	return otel.Generate(c)
}
func LoadAPIKeyCredentials(r io.Reader) ([]api.APIKeyCredential, error) {
	return gatewayconfig.LoadAPIKeyCredentials(r)
}
func APIKeySecret(namespace string, a api.Authenticator, c []api.APIKeyCredential) (*corev1.Secret, error) {
	return kubernetes.APIKeySecret(namespace, a, c)
}
func GenerateAPIKeyECDS(a api.Authenticator, c []api.APIKeyCredential) ([]byte, error) {
	return envoy.GenerateAPIKeyECDS(a, c)
}
