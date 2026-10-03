package config

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

// KubernetesMetrics configures the collector's scrape timing and resources.
type KubernetesMetrics struct {
	ScrapeInterval *Duration                      `yaml:"scrape_interval,omitempty"`
	ScrapeTimeout  *Duration                      `yaml:"scrape_timeout,omitempty"`
	Resources      KubernetesResourceRequirements `yaml:"resources,omitempty"`
}

func (m KubernetesMetrics) withDefaults() KubernetesMetrics {
	m.ScrapeInterval = defaultDuration(m.ScrapeInterval, 30*time.Second)
	m.ScrapeTimeout = defaultDuration(m.ScrapeTimeout, 10*time.Second)
	m.Resources.Requests = copyResourcesOrDefault(m.Resources.Requests, map[string]string{"cpu": "20m", "memory": "64Mi"})
	m.Resources.Limits = copyResourcesOrDefault(m.Resources.Limits, map[string]string{"memory": "256Mi"})
	return m
}

func (m KubernetesMetrics) validate() error {
	for _, field := range []struct {
		name  string
		value *Duration
	}{{"scrape_interval", m.ScrapeInterval}, {"scrape_timeout", m.ScrapeTimeout}} {
		if err := validateDuration("kubernetes.metrics."+field.name, field.value, false); err != nil {
			return err
		}
		if time.Duration(*field.value)%time.Millisecond != 0 {
			return fmt.Errorf("kubernetes.metrics.%s must be a whole number of milliseconds", field.name)
		}
	}
	if *m.ScrapeTimeout > *m.ScrapeInterval {
		return fmt.Errorf("kubernetes.metrics.scrape_timeout (%s) must not exceed kubernetes.metrics.scrape_interval (%s)", m.ScrapeTimeout, m.ScrapeInterval)
	}
	return validateKubernetesResourceRequirements("kubernetes.metrics.resources", m.Resources)
}

func validateKubernetesResourceRequirements(prefix string, requirements KubernetesResourceRequirements) error {
	for _, list := range []struct {
		name   string
		values map[string]string
	}{
		{name: "requests", values: requirements.Requests},
		{name: "limits", values: requirements.Limits},
	} {
		for _, name := range slices.Sorted(maps.Keys(list.values)) {
			if problems := validation.IsQualifiedName(name); len(problems) > 0 {
				return fmt.Errorf("%s.%s contains invalid resource name %q", prefix, list.name, name)
			}
			quantity, err := resource.ParseQuantity(list.values[name])
			if err != nil {
				return fmt.Errorf("%s.%s.%s must be a valid Kubernetes resource quantity: %w", prefix, list.name, name, err)
			}
			if quantity.Sign() < 0 {
				return fmt.Errorf("%s.%s.%s must not be negative", prefix, list.name, name)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(requirements.Requests)) {
		if limit, ok := requirements.Limits[name]; ok {
			request := resource.MustParse(requirements.Requests[name])
			if request.Cmp(resource.MustParse(limit)) > 0 {
				return fmt.Errorf("%s.requests.%s must not exceed %s.limits.%s", prefix, name, prefix, name)
			}
		}
	}
	return nil
}
