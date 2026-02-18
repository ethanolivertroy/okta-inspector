package cmd

import (
	"github.com/ethanolivertroy/okta-inspector/internal/capabilities"
	"github.com/spf13/cobra"
)

var (
	buildManifest string
	buildOutput   string
	buildOS       string
	buildArch     string
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Compile a restricted binary from a capability manifest",
	Long: `Build a custom okta-inspector binary that only includes specific
capabilities defined in a build.yaml manifest file.`,
	RunE: runBuild,
}

func init() {
	buildCmd.Flags().StringVar(&buildManifest, "manifest", "build.yaml", "path to capability manifest")
	buildCmd.Flags().StringVarP(&buildOutput, "output", "o", "okta-inspector-custom", "output binary path")
	buildCmd.Flags().StringVar(&buildOS, "os", "", "target OS (default: current)")
	buildCmd.Flags().StringVar(&buildArch, "arch", "", "target architecture (default: current)")
	rootCmd.AddCommand(buildCmd)
}

func runBuild(cmd *cobra.Command, args []string) error {
	manifest, err := capabilities.LoadManifest(buildManifest)
	if err != nil {
		return err
	}

	return capabilities.BuildRestricted(manifest, buildOutput, buildOS, buildArch)
}
