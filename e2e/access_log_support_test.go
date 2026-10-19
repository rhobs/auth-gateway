//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type envoyAccessLog struct {
	Status              int    `json:"status"`
	Path                string `json:"path"`
	ResponseCodeDetails string `json:"response_code_details"`
}

func envoyAccessLogs(ctx context.Context, namespace string) ([]envoyAccessLog, error) {
	podName, containers, err := env.PodContainerNames(ctx, namespace, gatewayPodSelector)
	if err != nil {
		return nil, err
	}
	hasEnvoy := false
	for _, name := range containers {
		if name == "envoy" {
			hasEnvoy = true
			break
		}
	}
	if !hasEnvoy {
		return nil, fmt.Errorf("Pod %q has no envoy container", podName)
	}

	logs, err := env.ContainerLogs(ctx, namespace, podName, "envoy", 0)
	if err != nil {
		return nil, err
	}
	var entries []envoyAccessLog
	for lineNumber, line := range strings.Split(string(logs), "\n") {
		if !strings.Contains(line, `"response_code_details"`) {
			continue
		}
		var entry envoyAccessLog
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("decode Envoy access log line %d: %w", lineNumber+1, err)
		}
		if entry.Status == 0 {
			return nil, fmt.Errorf("Envoy access log line %d has no status", lineNumber+1)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func envoyAccessLogAfter(ctx context.Context, namespace string, previousCount, status int) (envoyAccessLog, error) {
	entries, err := envoyAccessLogs(ctx, namespace)
	if err != nil {
		return envoyAccessLog{}, err
	}
	if len(entries) < previousCount {
		return envoyAccessLog{}, fmt.Errorf("access log count fell from %d to %d", previousCount, len(entries))
	}
	for _, entry := range entries[previousCount:] {
		if entry.Status == status {
			return entry, nil
		}
	}
	return envoyAccessLog{}, fmt.Errorf("no new HTTP %d access log; got %+v", status, entries[previousCount:])
}
