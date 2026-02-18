package tui

import (
	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// Custom tea.Msg types for the TUI.

// AuditCompleteMsg is sent when an audit finishes.
type AuditCompleteMsg struct {
	Result *engine.AuditResult
	Err    error
}

// AuditProgressMsg reports audit progress.
type AuditProgressMsg struct {
	Phase   string
	Current int
	Total   int
	Message string
}

// NavigateMsg requests navigation to a different view.
type NavigateMsg struct {
	View        ViewState
	FrameworkID string
	Finding     *engine.Finding
}

// ViewState represents which screen is active.
type ViewState int

const (
	ViewDashboard ViewState = iota
	ViewFrameworkList
	ViewFindings
	ViewFindingDetail
	ViewAuditProgress
)
