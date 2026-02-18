package capabilities

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadManifest reads a capability manifest from a YAML file.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	return &m, nil
}

// Validate checks that the manifest only references known capabilities.
func (m *Manifest) Validate() error {
	known := make(map[string]bool)
	for _, f := range AllFrameworks {
		known[f] = true
	}
	for _, f := range m.Capabilities.Frameworks {
		if !known[f] {
			return fmt.Errorf("unknown framework in manifest: %s", f)
		}
	}

	knownCmds := make(map[string]bool)
	for _, c := range AllCommands {
		knownCmds[c] = true
	}
	for _, c := range m.Capabilities.Commands {
		if !knownCmds[c] {
			return fmt.Errorf("unknown command in manifest: %s", c)
		}
	}

	knownScopes := make(map[string]bool)
	for _, s := range AllScopes {
		knownScopes[s] = true
	}
	for _, s := range m.Capabilities.APIScopes {
		if !knownScopes[s] {
			return fmt.Errorf("unknown API scope in manifest: %s", s)
		}
	}

	return nil
}

// HasFramework checks if the manifest allows a given framework.
func (m *Manifest) HasFramework(id string) bool {
	for _, f := range m.Capabilities.Frameworks {
		if f == id {
			return true
		}
	}
	return false
}

// HasCommand checks if the manifest allows a given command.
func (m *Manifest) HasCommand(name string) bool {
	for _, c := range m.Capabilities.Commands {
		if c == name {
			return true
		}
	}
	return false
}
