//go:build e2e

package framework

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/onsi/ginkgo/v2"
)

func writeEnvoyAdminDiagnostic(ctx context.Context, dir, address, filename, path string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		writeDiagnostic(dir, filename, nil, err)
		return
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		writeDiagnostic(dir, filename, nil, err)
		return
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if err := errors.Join(err, closeErr); err != nil {
		writeDiagnostic(dir, filename, nil, fmt.Errorf("read Envoy admin response: %w", err))
		return
	}
	writeDiagnostic(dir, filename, data, nil)
	writeGinkgo("Envoy auth stats (HTTP %d):\n%s\n", response.StatusCode, data)
}

func writeDiagnostic(dir, name string, value any, err error) {
	var data []byte
	if err != nil {
		data = []byte("error: " + err.Error() + "\n")
	} else if raw, ok := value.([]byte); ok {
		data = raw
	} else {
		var marshalErr error
		data, marshalErr = json.MarshalIndent(value, "", "  ")
		if marshalErr != nil {
			data = []byte("encode diagnostic: " + marshalErr.Error() + "\n")
		} else {
			data = append(data, '\n')
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		writeGinkgo("write diagnostic %s: %v\n", name, err)
	}
}

func writeGinkgo(format string, args ...any) {
	if _, err := fmt.Fprintf(ginkgo.GinkgoWriter, format, args...); err != nil {
		log.Printf(format, args...)
		log.Printf("write Ginkgo output: %v", err)
	}
}
