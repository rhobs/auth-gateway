package config

import (
	"fmt"
	"math"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func cloneAdmissionControlConfig(c gatewayapi.AdmissionControlConfig) gatewayapi.AdmissionControlConfig {
	c.SamplingWindow = clonePointer(c.SamplingWindow)
	c.SrThreshold = clonePointer(c.SrThreshold)
	c.RPSThreshold = clonePointer(c.RPSThreshold)
	c.MaxRejectionProbability = clonePointer(c.MaxRejectionProbability)
	return c
}

func validateAdmissionControlConfig(c gatewayapi.AdmissionControlConfig, name string) error {
	if err := validateDuration(name+".sampling_window", c.SamplingWindow, false); err != nil {
		return err
	}
	for _, value := range []struct {
		Name  string
		Value *float64
	}{
		{"sr_threshold", c.SrThreshold},
		{"max_rejection_probability", c.MaxRejectionProbability},
	} {
		if value.Value == nil {
			continue
		}
		if math.IsNaN(*value.Value) || math.IsInf(*value.Value, 0) || *value.Value < 0 || *value.Value > 100 {
			return fmt.Errorf("%s.%s must be between 0 and 100", name, value.Name)
		}
	}
	return nil
}

const AdmissionControlFilterName = "envoy.filters.http.admission_control"

func AdmissionChainName(apiName string) string {
	return "admission-" + apiName
}
