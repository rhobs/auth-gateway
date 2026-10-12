//go:build e2e

package framework

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/onsi/ginkgo/v2"
)

func (e *Environment) writeEnvoyAdminDiagnostic(ctx context.Context, dir, address, filename, path string) {
	data, err := e.EnvoyAdminGet(ctx, address, path)
	if err != nil {
		writeDiagnostic(dir, filename, nil, err)
		return
	}
	writeDiagnostic(dir, filename, data, nil)
	writeGinkgo("Envoy auth stats:\n%s\n", data)
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
