package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethanolivertroy/okta-inspector/internal/app"
	"github.com/ethanolivertroy/okta-inspector/internal/config"
	"github.com/spf13/cobra"
)

var (
	auditOutputDir    string
	auditFrameworks   string
	auditFormat       string
	auditFromSnapshot string
	auditSaveSnapshot bool
	auditJSON         bool
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run compliance audit against an Okta tenant",
	Long: `Audit an Okta tenant against multiple compliance frameworks.

Frameworks: stig, fedramp, irap, ismap, soc2, pcidss (default: all)`,
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVarP(&auditOutputDir, "output-dir", "o", "", "output directory")
	auditCmd.Flags().StringVarP(&auditFrameworks, "frameworks", "f", "", "comma-separated framework IDs")
	auditCmd.Flags().StringVar(&auditFormat, "format", "both", "output format: markdown, json, both")
	auditCmd.Flags().StringVar(&auditFromSnapshot, "from-snapshot", "", "analyze saved snapshot instead of calling API")
	auditCmd.Flags().BoolVar(&auditSaveSnapshot, "save-snapshot", true, "save raw API data as snapshot")
	auditCmd.Flags().BoolVar(&auditJSON, "json", false, "output findings as JSON to stdout")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	// Resolve domain
	domain, err := config.ResolveDomain(flagDomain)
	if err != nil && auditFromSnapshot == "" {
		return err
	}

	// Resolve auth (not needed for snapshot-only mode)
	var authHeader string
	if auditFromSnapshot == "" {
		auth, err := config.ResolveAuth(flagToken, flagOAuth)
		if err != nil {
			return err
		}
		authHeader = auth.AuthHeader()
	}

	// Parse framework list
	var frameworks []string
	if auditFrameworks != "" {
		frameworks = strings.Split(auditFrameworks, ",")
		for i := range frameworks {
			frameworks[i] = strings.TrimSpace(frameworks[i])
		}
	}

	// Build options
	opts := app.Options{
		Domain:       domain,
		AuthHeader:   authHeader,
		OutputDir:    auditOutputDir,
		Frameworks:   frameworks,
		Format:       auditFormat,
		SaveSnapshot: auditSaveSnapshot,
		FromSnapshot: auditFromSnapshot,
		Quiet:        flagQuiet,
	}

	if !flagQuiet {
		opts.OnProgress = func(phase string, current, total int, message string) {
			if total > 0 {
				fmt.Fprintf(os.Stderr, "[%s] (%d/%d) %s\n", phase, current, total, message)
			} else {
				fmt.Fprintf(os.Stderr, "[%s] %s\n", phase, message)
			}
		}
	}

	// Run audit
	a := app.New(opts)
	result, err := a.RunAudit(context.Background())
	if err != nil {
		return err
	}

	// JSON output to stdout if requested
	if auditJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Print summary
	if !flagQuiet {
		fmt.Fprintf(os.Stderr, "\n=== Audit Complete ===\n")
		fmt.Fprintf(os.Stderr, "Frameworks: %d | Findings: %d | Pass: %d | Fail: %d | Manual: %d\n",
			len(result.Frameworks), result.TotalFindings,
			result.TotalPass, result.TotalFail, result.TotalManual)
		fmt.Fprintf(os.Stderr, "API calls: %d\n", result.APICallCount)
		if auditOutputDir != "" {
			fmt.Fprintf(os.Stderr, "Results: %s\n", auditOutputDir)
		}
	}

	return nil
}
