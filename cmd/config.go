package cmd

import (
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(config.DefaultConfigPath())
		if err != nil {
			return err
		}

		data, err := yaml.Marshal(cfg)
		if err != nil {
			return err
		}

		fmt.Printf("# Config file: %s\n", config.DefaultConfigPath())
		fmt.Print(string(data))
		return nil
	},
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create configuration file interactively",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := config.DefaultConfigPath()
		cfg := &config.Config{
			PageSize: config.DefaultPageSize,
			MaxPages: config.DefaultMaxPages,
			Format:   "both",
		}

		if flagDomain != "" {
			cfg.Domain = flagDomain
		}

		if err := cfg.Save(path); err != nil {
			return err
		}

		fmt.Printf("Configuration written to %s\n", path)
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := config.DefaultConfigPath()
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}

		switch args[0] {
		case "domain":
			cfg.Domain = args[1]
		case "format":
			cfg.Format = args[1]
		case "output_dir":
			cfg.OutputDir = args[1]
		default:
			return fmt.Errorf("unknown config key: %s", args[0])
		}

		if err := cfg.Save(path); err != nil {
			return err
		}

		fmt.Printf("Set %s = %s\n", args[0], args[1])
		return nil
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}
