//go:build e2e

package framework

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// BuildAndLoadGoImage builds a static test binary and loads its image into Kind.
func (e *Environment) BuildAndLoadGoImage(ctx context.Context, packagePath, image string) error {
	if !strings.HasPrefix(e.KubeContext(), "kind-") {
		return fmt.Errorf("image loading requires a Kind context, got %q", e.KubeContext())
	}
	directory, err := os.MkdirTemp("", "auth-gateway-e2e-image-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(directory) }()
	if err := os.WriteFile(filepath.Join(directory, "Dockerfile"), []byte("FROM scratch\nCOPY server /server\nUSER 65532:65532\nENTRYPOINT [\"/server\"]\n"), 0600); err != nil {
		return err
	}
	configDir := filepath.Join(directory, "docker-config")
	if err := os.Mkdir(configDir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}\n"), 0600); err != nil {
		return err
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(directory, "server"), packagePath)
	build.Dir = e.Root
	build.Env = append(build.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build test server: %w: %s", err, output)
	}
	docker := exec.CommandContext(ctx, "docker", "build", "--tag", image, directory)
	docker.Env = append(docker.Environ(), "DOCKER_CONFIG="+configDir)
	if output, err := docker.CombinedOutput(); err != nil {
		return fmt.Errorf("build test image: %w: %s", err, output)
	}
	kind := exec.CommandContext(ctx, "go", "-C", filepath.Join(e.Root, "e2e", "tools"), "tool", "kind", "load", "docker-image", "--name", strings.TrimPrefix(e.KubeContext(), "kind-"), image)
	kind.Env = append(kind.Environ(), "DOCKER_CONFIG="+configDir)
	if output, err := kind.CombinedOutput(); err != nil {
		return fmt.Errorf("load test image into Kind: %w: %s", err, output)
	}
	return nil
}
