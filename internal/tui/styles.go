package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	primary   = lipgloss.Color("#7C3AED") // purple
	secondary = lipgloss.Color("#06B6D4") // cyan
	success   = lipgloss.Color("#10B981") // green
	danger    = lipgloss.Color("#EF4444") // red
	warning   = lipgloss.Color("#F59E0B") // amber
	info      = lipgloss.Color("#3B82F6") // blue
	muted     = lipgloss.Color("#6B7280") // gray
	subtle    = lipgloss.Color("#374151") // dark gray

	// Styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primary).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(secondary)

	StatusBarStyle = lipgloss.NewStyle().
			Background(subtle).
			Foreground(lipgloss.Color("#F9FAFB")).
			Padding(0, 1)

	HelpStyle = lipgloss.NewStyle().
			Foreground(muted).
			MarginTop(1)

	// Badges
	PassBadge = lipgloss.NewStyle().
			Background(success).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1).
			Bold(true)

	FailBadge = lipgloss.NewStyle().
			Background(danger).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1).
			Bold(true)

	ManualBadge = lipgloss.NewStyle().
			Background(warning).
			Foreground(lipgloss.Color("#000000")).
			Padding(0, 1).
			Bold(true)

	ErrorBadge = lipgloss.NewStyle().
			Background(danger).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	// Severity badges
	CriticalBadge = lipgloss.NewStyle().Background(lipgloss.Color("#7F1D1D")).Foreground(lipgloss.Color("#FFF")).Padding(0, 1)
	HighBadge     = lipgloss.NewStyle().Background(danger).Foreground(lipgloss.Color("#FFF")).Padding(0, 1)
	MediumBadge   = lipgloss.NewStyle().Background(warning).Foreground(lipgloss.Color("#000")).Padding(0, 1)
	LowBadge      = lipgloss.NewStyle().Background(info).Foreground(lipgloss.Color("#FFF")).Padding(0, 1)
	InfoBadge     = lipgloss.NewStyle().Background(muted).Foreground(lipgloss.Color("#FFF")).Padding(0, 1)

	// Layout
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(subtle).
			Padding(1, 2)

	SelectedStyle = lipgloss.NewStyle().
			Foreground(primary).
			Bold(true)

	NormalStyle = lipgloss.NewStyle()
)

// SeverityBadge returns the appropriate badge style for a severity level.
func SeverityBadge(sev string) string {
	switch sev {
	case "critical":
		return CriticalBadge.Render("CRIT")
	case "high":
		return HighBadge.Render("HIGH")
	case "medium":
		return MediumBadge.Render("MED")
	case "low":
		return LowBadge.Render("LOW")
	default:
		return InfoBadge.Render("INFO")
	}
}

// StatusBadge returns the appropriate badge for a status.
func StatusBadge(status string) string {
	switch status {
	case "pass":
		return PassBadge.Render("PASS")
	case "fail":
		return FailBadge.Render("FAIL")
	case "manual":
		return ManualBadge.Render("MANUAL")
	case "error":
		return ErrorBadge.Render("ERROR")
	default:
		return InfoBadge.Render("N/A")
	}
}
