//go:build e2e

package framework

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const envoyAdminResponseLimit = 1 << 20

// EnvoyAdminGet sends a GET request to a forwarded Envoy admin address.
func (e *Environment) EnvoyAdminGet(ctx context.Context, address, path string) ([]byte, error) {
	if address == "" || !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("envoy admin GET requires an address and an absolute path")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create Envoy admin request: %w", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request Envoy admin path %q: %w", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, envoyAdminResponseLimit))
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, fmt.Errorf("read Envoy admin path %q: %w", path, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("envoy admin path %q returned HTTP %d: %s", path, response.StatusCode, data)
	}
	return data, nil
}
