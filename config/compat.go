// Package config preserves the original import path until e2e callers migrate to pkg/gateway.
package config

import (
	"github.com/rhobs/auth-gateway/pkg/api"

	"io"
	"time"

	"github.com/rhobs/auth-gateway/pkg/gateway"
	corev1 "k8s.io/api/core/v1"
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
	GeneratedFile                  = gateway.GeneratedFile
	GeneratedFiles                 = gateway.GeneratedFiles
	KubernetesResources            = gateway.KubernetesResources
)

const (
	DefaultEnvoyImage         = gateway.DefaultEnvoyImage
	DefaultOTelCollectorImage = gateway.DefaultOTelCollectorImage
	EnvoyConfigDirectory      = gateway.EnvoyConfigDirectory
	APIKeyConfigDirectory     = gateway.APIKeyConfigDirectory
	TrustedCADirectory        = gateway.TrustedCADirectory
	EnvoyBootstrapPath        = gateway.EnvoyBootstrapPath
	APIKeyECDSPath            = gateway.APIKeyECDSPath
)

func Load(r io.Reader) (api.Config, error)                  { return gateway.Load(r) }
func Validate(c api.Config) error                           { return gateway.Validate(c) }
func NewDuration(v time.Duration) *api.Duration             { return api.NewDuration(v) }
func Generate(c api.Config) (gateway.GeneratedFiles, error) { return gateway.Generate(c) }
func GenerateKubernetes(c api.Config) (*gateway.KubernetesResources, error) {
	return gateway.GenerateKubernetes(c)
}
func GenerateOTelCollectorConfig(c api.Config) ([]byte, error) {
	return gateway.GenerateOTelCollectorConfig(c)
}
func LoadAPIKeyCredentials(r io.Reader) ([]api.APIKeyCredential, error) {
	return gateway.LoadAPIKeyCredentials(r)
}
func APIKeySecret(namespace string, a api.Authenticator, c []api.APIKeyCredential) (*corev1.Secret, error) {
	return gateway.APIKeySecret(namespace, a, c)
}
func GenerateAPIKeyECDS(a api.Authenticator, c []api.APIKeyCredential) ([]byte, error) {
	return gateway.GenerateAPIKeyECDS(a, c)
}
