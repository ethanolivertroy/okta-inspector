package cmd

import (
	"github.com/spf13/cobra"
)

var (
	flagDomain string
	flagToken  string
	flagOAuth  bool
	flagQuiet  bool
)

var rootCmd = &cobra.Command{
	Use:   "okta-inspector",
	Short: "Okta multi-framework compliance audit tool",
	Long: `okta-inspector audits Okta tenants against multiple compliance frameworks
including DISA STIG, FedRAMP, IRAP, ISMAP, SOC 2, and PCI-DSS 4.0.

Run interactively with a TUI, as a CLI for CI/CD, or as an MCP server
for AI assistant integration.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagDomain, "domain", "d", "", "Okta domain (e.g., your-org.okta.com)")
	rootCmd.PersistentFlags().StringVarP(&flagToken, "token", "t", "", "Okta API token (or set OKTA_API_TOKEN)")
	rootCmd.PersistentFlags().BoolVar(&flagOAuth, "oauth", false, "use OAuth bearer token instead of SSWS")
	rootCmd.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "suppress progress output")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
