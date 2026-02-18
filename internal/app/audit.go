package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
	"github.com/ethanolivertroy/okta-inspector/internal/okta"
)

// RunAudit executes the 3-phase audit pipeline.
func (a *App) RunAudit(ctx context.Context) (*engine.AuditResult, error) {
	// Phase 1: Collection
	snap, err := a.collectData(ctx)
	if err != nil {
		return nil, fmt.Errorf("phase 1 (collection): %w", err)
	}

	// Phase 2: Analysis
	result, err := a.analyzeData(ctx, snap)
	if err != nil {
		return nil, fmt.Errorf("phase 2 (analysis): %w", err)
	}

	result.APICallCount = a.Client.APICallCount()

	// Phase 3: Reporting
	if err := a.generateReports(ctx, result); err != nil {
		return nil, fmt.Errorf("phase 3 (reporting): %w", err)
	}

	return result, nil
}

// collectData handles Phase 1: data collection from Okta or snapshot file.
func (a *App) collectData(ctx context.Context) (*okta.Snapshot, error) {
	// Load from existing snapshot if specified
	if a.Options.FromSnapshot != "" {
		return okta.LoadSnapshot(a.Options.FromSnapshot)
	}

	// Test connection first
	if err := a.Client.TestConnection(ctx); err != nil {
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	// Collect live data
	snap, err := a.Client.CollectSnapshot(ctx, a.Options.Domain)
	if err != nil {
		return nil, err
	}

	// Save snapshot if requested
	if a.Options.SaveSnapshot {
		outDir := a.resolveOutputDir()
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return nil, fmt.Errorf("creating output dir: %w", err)
		}
		snapPath := filepath.Join(outDir, "snapshot.json")
		if err := snap.SaveToFile(snapPath); err != nil {
			return nil, fmt.Errorf("saving snapshot: %w", err)
		}
	}

	return snap, nil
}

// analyzeData handles Phase 2: run compliance checks against snapshot.
func (a *App) analyzeData(ctx context.Context, snap *okta.Snapshot) (*engine.AuditResult, error) {
	ec := engine.NewEvalContext(snap, a.Options.Domain)
	return a.Engine.Evaluate(ctx, ec, nil)
}

// generateReports handles Phase 3: generate output reports.
func (a *App) generateReports(_ context.Context, result *engine.AuditResult) error {
	outDir := a.resolveOutputDir()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	format := a.Options.Format
	if format == "" {
		format = "both"
	}

	if format == "json" || format == "both" {
		if err := writeJSON(filepath.Join(outDir, "audit_results.json"), result); err != nil {
			return err
		}
	}

	if format == "markdown" || format == "both" {
		if err := writeMarkdownReport(outDir, result); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) resolveOutputDir() string {
	if a.Options.OutputDir != "" {
		return a.Options.OutputDir
	}
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("okta_audit_results_%s", timestamp)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func writeMarkdownReport(outDir string, result *engine.AuditResult) error {
	// Executive Summary
	summary := fmt.Sprintf(`# Okta Security Audit - Executive Summary
Generated: %s
Domain: %s

## Overview
This audit evaluates Okta configuration against %d compliance frameworks.

## Findings Summary
- **Total Findings**: %d
- **Pass**: %d
- **Fail**: %d
- **Manual Review**: %d

## Framework Results
`, result.Timestamp.Format(time.RFC3339), result.Domain,
		len(result.Frameworks), result.TotalFindings,
		result.TotalPass, result.TotalFail, result.TotalManual)

	for _, fw := range result.Frameworks {
		summary += fmt.Sprintf("\n### %s\n", fw.FrameworkName)
		summary += fmt.Sprintf("- Pass: %d\n- Fail: %d\n- Manual: %d\n- Errors: %d\n",
			fw.PassCount, fw.FailCount, fw.ManualCount, fw.ErrorCount)

		// List failures
		for _, f := range fw.Findings {
			if f.Status == engine.StatusFail {
				summary += fmt.Sprintf("- **FAIL** [%s] %s: %s\n", f.CheckID, f.Title, f.Comments)
			}
		}
	}

	summary += "\n## Manual Verification Required\n"
	hasManual := false
	for _, fw := range result.Frameworks {
		for _, f := range fw.Findings {
			if f.Status == engine.StatusManual {
				summary += fmt.Sprintf("- [%s] %s: %s\n", f.CheckID, f.Title, f.Comments)
				hasManual = true
			}
		}
	}
	if !hasManual {
		summary += "No manual checks identified.\n"
	}

	if err := os.WriteFile(filepath.Join(outDir, "executive_summary.md"), []byte(summary), 0o600); err != nil {
		return err
	}

	// Per-framework reports
	for _, fw := range result.Frameworks {
		report := fmt.Sprintf("# %s Compliance Report\nGenerated: %s\nDomain: %s\n\n",
			fw.FrameworkName, result.Timestamp.Format(time.RFC3339), result.Domain)

		report += fmt.Sprintf("## Summary\n- Pass: %d\n- Fail: %d\n- Manual: %d\n\n## Findings\n\n",
			fw.PassCount, fw.FailCount, fw.ManualCount)

		for _, f := range fw.Findings {
			icon := "PASS"
			switch f.Status {
			case engine.StatusFail:
				icon = "FAIL"
			case engine.StatusManual:
				icon = "MANUAL"
			case engine.StatusError:
				icon = "ERROR"
			}
			report += fmt.Sprintf("### [%s] %s - %s\n- **Status**: %s\n- **Severity**: %s\n- **Comments**: %s\n",
				icon, f.CheckID, f.Title, f.Status, f.Severity, f.Comments)
			if f.Remediation != "" {
				report += fmt.Sprintf("- **Remediation**: %s\n", f.Remediation)
			}
			report += "\n"
		}

		filename := filepath.Join(outDir, fmt.Sprintf("%s_report.md", fw.FrameworkID))
		if err := os.WriteFile(filename, []byte(report), 0o600); err != nil {
			return err
		}
	}

	// Compliance matrix
	matrix := fmt.Sprintf(`# Unified Compliance Matrix
Generated: %s
Domain: %s

This matrix shows cross-framework control mappings.

| Check ID | Framework | Status | Cross-References |
|----------|-----------|--------|------------------|
`, result.Timestamp.Format(time.RFC3339), result.Domain)

	for _, fw := range result.Frameworks {
		for _, f := range fw.Findings {
			crossRefs := ""
			for fwID, controls := range f.CrossReferences {
				for _, ctrl := range controls {
					if crossRefs != "" {
						crossRefs += ", "
					}
					crossRefs += fwID + ":" + ctrl
				}
			}
			matrix += fmt.Sprintf("| %s | %s | %s | %s |\n", f.CheckID, fw.FrameworkID, f.Status, crossRefs)
		}
	}

	return os.WriteFile(filepath.Join(outDir, "compliance_matrix.md"), []byte(matrix), 0o600)
}
