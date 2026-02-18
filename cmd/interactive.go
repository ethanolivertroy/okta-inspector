package cmd

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ethanolivertroy/okta-inspector/internal/app"
	"github.com/ethanolivertroy/okta-inspector/internal/config"
	"github.com/ethanolivertroy/okta-inspector/internal/tui"
	"github.com/spf13/cobra"
)

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Launch interactive TUI",
	RunE:  runInteractive,
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}

func runInteractive(cmd *cobra.Command, args []string) error {
	domain, _ := config.ResolveDomain(flagDomain)
	if domain == "" {
		domain = "not configured"
	}

	m := tui.New(domain)

	// If we have credentials (via flag or env), pre-run an audit
	auth, authErr := config.ResolveAuth(flagToken, flagOAuth)
	if flagDomain != "" && authErr == nil {
		opts := app.Options{
			Domain:       domain,
			AuthHeader:   auth.AuthHeader(),
			SaveSnapshot: true,
			Format:       "both",
		}
		a := app.New(opts)
		result, err := a.RunAudit(context.Background())
		if err != nil {
			fmt.Printf("Warning: audit failed: %v\n", err)
		} else {
			m.SetResult(result)
		}
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
