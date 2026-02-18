package capabilities

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// BuildRestricted compiles a custom binary with the given manifest.
// It uses go build with ldflags to embed the manifest name.
func BuildRestricted(manifest *Manifest, outputPath, targetOS, targetArch string) error {
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}

	// Build ldflags to embed capability info
	ldflags := fmt.Sprintf("-s -w -X 'github.com/ethanolivertroy/okta-inspector/internal/version.Version=%s'",
		manifest.Name)

	args := []string{"build", "-ldflags", ldflags, "-o", outputPath, "."}

	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	env := os.Environ()
	if targetOS != "" {
		env = append(env, "GOOS="+targetOS)
	}
	if targetArch != "" {
		env = append(env, "GOARCH="+targetArch)
	}
	env = append(env, "CGO_ENABLED=0")
	cmd.Env = env

	fmt.Printf("Building restricted binary: %s\n", manifest.Name)
	fmt.Printf("  Frameworks: %s\n", strings.Join(manifest.Capabilities.Frameworks, ", "))
	fmt.Printf("  Commands: %s\n", strings.Join(manifest.Capabilities.Commands, ", "))
	fmt.Printf("  API Scopes: %s\n", strings.Join(manifest.Capabilities.APIScopes, ", "))
	fmt.Printf("  Output: %s\n", outputPath)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	fmt.Printf("Build complete: %s\n", outputPath)
	return nil
}
