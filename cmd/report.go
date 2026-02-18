package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
	"github.com/spf13/cobra"
)

var (
	reportInput      string
	reportFrameworks string
	reportOutputDir  string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from saved audit data",
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVarP(&reportInput, "input", "i", "", "path to audit result JSON")
	reportCmd.Flags().StringVarP(&reportFrameworks, "frameworks", "f", "", "comma-separated framework IDs to include")
	reportCmd.Flags().StringVarP(&reportOutputDir, "output-dir", "o", "", "output directory for reports")
	_ = reportCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(reportInput)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var result engine.AuditResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing audit result: %w", err)
	}

	// Filter frameworks if specified
	if reportFrameworks != "" {
		allowed := make(map[string]bool)
		for _, id := range strings.Split(reportFrameworks, ",") {
			allowed[strings.TrimSpace(id)] = true
		}
		var filtered []engine.FrameworkResult
		for _, fw := range result.Frameworks {
			if allowed[fw.FrameworkID] {
				filtered = append(filtered, fw)
			}
		}
		result.Frameworks = filtered
		result.Tally()
	}

	outDir := reportOutputDir
	if outDir == "" {
		outDir = fmt.Sprintf("okta_report_%s", time.Now().Format("20060102_150405"))
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	// Generate summary
	summary := fmt.Sprintf("# Okta Compliance Report\nGenerated: %s\nDomain: %s\n\n## Summary\n- Findings: %d\n- Pass: %d\n- Fail: %d\n- Manual: %d\n\n",
		result.Timestamp.Format(time.RFC3339), result.Domain,
		result.TotalFindings, result.TotalPass, result.TotalFail, result.TotalManual)

	for _, fw := range result.Frameworks {
		summary += fmt.Sprintf("### %s\n- Pass: %d | Fail: %d | Manual: %d\n\n",
			fw.FrameworkName, fw.PassCount, fw.FailCount, fw.ManualCount)
	}

	if err := os.WriteFile(filepath.Join(outDir, "report.md"), []byte(summary), 0o644); err != nil {
		return err
	}

	fmt.Printf("Report written to %s\n", outDir)
	return nil
}
