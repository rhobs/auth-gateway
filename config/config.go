package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	yaml "go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	configVersion            = 1
	defaultNodeID            = "auth-gateway"
	defaultNodeCluster       = "auth-gateway"
	invalidControlCharacters = "\r\n\x00"
)

var apiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")

// Config describes gateway behavior, observability, and optional Kubernetes output.
type Config struct {
	Version               int                   `yaml:"version"`
	Node                  EnvoyNode             `yaml:"node,omitempty"`
	Listener              Listener              `yaml:"listener"`
	Overload              *OverloadConfig       `yaml:"overload,omitempty"`
	Authenticators        []Authenticator       `yaml:"authenticators,omitempty"`
	AuthorizationPolicies []AuthorizationPolicy `yaml:"authorization_policies,omitempty"`
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

func validateGatewayName(fieldPath, value string) error {
	if !apiNamePattern.MatchString(value) {
		return fmt.Errorf("%s.name must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens", fieldPath)
	}
	return nil
}

// Load decodes one strict YAML document, applies defaults, and validates it.
// API and route timeout overrides stay as supplied, including omitted values.
// Validation checks their effective values; generation resolves them on a copy.
// On failure, Load returns the zero Config and a non-nil error.
func Load(r io.Reader) (Config, error) {
	if r == nil {
		return Config{}, fmt.Errorf("read gateway configuration: input is nil")
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}
	var c Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		var durationError *durationYAMLError
		if errors.As(err, &durationError) {
			var document yaml.Node
			if yaml.Unmarshal(data, &document) == nil {
				if field := yamlPathAtPosition(&document, durationError.line, durationError.column, ""); field != "" {
					return Config{}, fmt.Errorf("%s: %w", field, err)
				}
			}
		}
		return Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, fmt.Errorf("read gateway configuration: expected exactly one YAML document")
	} else if err != io.EOF {
		return Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}

	c = c.withDefaults()
	if _, err := validateDefaultedConfig(c, false); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks whether c follows the public configuration contract.
// Use it when building a Config in Go instead of loading YAML with Load.
func (c Config) Validate() error {
	_, err := validateDefaultedConfig(c.withDefaults(), false)
	return err
}

func (c Config) validateBaseSettings(metricsEnabled, tracingEnabled bool) error {
	if c.Version != configVersion {
		return fmt.Errorf("version must be %d", configVersion)
	}
	if strings.TrimSpace(c.Node.ID) == "" {
		return fmt.Errorf("node.id must not be empty")
	}
	if strings.TrimSpace(c.Node.Cluster) == "" {
		return fmt.Errorf("node.cluster must not be empty")
	}
	if err := c.Listener.validate(metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	if err := c.Observability.Metrics.validate(); err != nil {
		return err
	}
	if err := c.Observability.Tracing.validate(); err != nil {
		return err
	}
	return nil
}

func (c Config) withDefaults() Config {
	c = c.clone()
	for i := range c.Authenticators {
		c.Authenticators[i] = c.Authenticators[i].withDefaults()
	}
	if c.Node.ID == "" {
		c.Node.ID = defaultNodeID
	}
	if c.Node.Cluster == "" {
		c.Node.Cluster = defaultNodeCluster
	}
	c.Listener = c.Listener.withDefaults()
	if c.Overload != nil {
		overload := c.Overload.withDefaults()
		c.Overload = &overload
	}
	c.Observability = c.Observability.withDefaults(c.Node.Cluster)
	for i := range c.Servers {
		if c.Servers[i].TLSConfig != nil {
			tlsConfig := c.Servers[i].TLSConfig.withDefaults()
			c.Servers[i].TLSConfig = &tlsConfig
		}
	}
	for i := range c.APIs {
		c.APIs[i].Upstream = c.APIs[i].Upstream.withDefaults()
	}
	for i := range c.APIs {
		c.APIs[i].CircuitBreakers = c.APIs[i].CircuitBreakers.withDefaults()
	}
	if c.Kubernetes != nil {
		kubernetes := c.Kubernetes.withDefaults(c.hasHTTPS())
		c.Kubernetes = &kubernetes
	}
	return c
}

func validHost(value string) bool {
	return net.ParseIP(value) != nil || validDNSHost(value)
}

func validDNSHost(value string) bool {
	return net.ParseIP(value) == nil && len(validation.IsDNS1123Subdomain(value)) == 0
}

func (c Config) clone() Config {
	c.Listener = c.Listener.clone()
	c.Overload = cloneConfigPointer(c.Overload)
	c.Authenticators = cloneSlice(c.Authenticators)
	c.AuthorizationPolicies = cloneSlice(c.AuthorizationPolicies)
	c.Servers = cloneSlice(c.Servers)
	c.APIs = cloneSlice(c.APIs)
	c.Observability = c.Observability.clone()
	c.Kubernetes = cloneConfigPointer(c.Kubernetes)
	return c
}
