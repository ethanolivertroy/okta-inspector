package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all application configuration.
type Config struct {
	Domain     string   `yaml:"domain"`
	Token      string   `yaml:"token,omitempty"`
	OAuth      bool     `yaml:"oauth,omitempty"`
	OutputDir  string   `yaml:"output_dir,omitempty"`
	Frameworks []string `yaml:"frameworks,omitempty"`
	Format     string   `yaml:"format,omitempty"`
	PageSize   int      `yaml:"page_size,omitempty"`
	MaxPages   int      `yaml:"max_pages,omitempty"`
}

// Load reads configuration from the YAML config file at path.
// Returns an empty Config (with defaults) if the file does not exist.
func Load(path string) (*Config, error) {
	cfg := &Config{
		PageSize: DefaultPageSize,
		MaxPages: DefaultMaxPages,
		Format:   "both",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

// Save writes the configuration to the YAML config file at path.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// DefaultConfigPath returns ~/.okta-inspector/okta-inspector.yaml.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return DefaultConfigFile
	}
	return filepath.Join(home, DefaultConfigDir, DefaultConfigFile)
}
