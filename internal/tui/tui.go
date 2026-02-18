package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// Model is the root TUI model.
type Model struct {
	// State
	view        ViewState
	result      *engine.AuditResult
	frameworks  []engine.FrameworkResult
	selectedFW  int
	selectedIdx int
	findings    []engine.Finding
	detail      *engine.Finding
	err         error

	// Audit in progress
	auditing bool
	spinner  spinner.Model
	progress string

	// Config
	domain string
	width  int
	height int
}

// New creates the root TUI model.
func New(domain string) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return Model{
		view:   ViewDashboard,
		domain: domain,
		spinner: s,
	}
}

// SetResult loads audit results into the TUI.
func (m *Model) SetResult(r *engine.AuditResult) {
	m.result = r
	m.frameworks = r.Frameworks
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, Keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, Keys.Back):
			return m.navigateBack(), nil
		}

	case AuditCompleteMsg:
		m.auditing = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.SetResult(msg.Result)
		}
		m.view = ViewDashboard
		return m, nil

	case AuditProgressMsg:
		m.progress = fmt.Sprintf("[%s] (%d/%d) %s", msg.Phase, msg.Current, msg.Total, msg.Message)
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	// Delegate to view-specific update
	switch m.view {
	case ViewDashboard:
		return m.updateDashboard(msg)
	case ViewFrameworkList:
		return m.updateFrameworkList(msg)
	case ViewFindings:
		return m.updateFindings(msg)
	case ViewFindingDetail:
		return m, nil
	case ViewAuditProgress:
		return m, nil
	}

	return m, nil
}

func (m Model) View() string {
	if m.err != nil {
		return BoxStyle.Render(fmt.Sprintf("Error: %v\n\nPress q to quit.", m.err))
	}

	var content string
	switch m.view {
	case ViewDashboard:
		content = m.viewDashboard()
	case ViewFrameworkList:
		content = m.viewFrameworkList()
	case ViewFindings:
		content = m.viewFindings()
	case ViewFindingDetail:
		content = m.viewFindingDetail()
	case ViewAuditProgress:
		content = m.viewAuditProgress()
	}

	// Status bar
	status := StatusBarStyle.Render(fmt.Sprintf(" okta-inspector | %s | %s ", m.domain, viewName(m.view)))
	help := HelpStyle.Render("q: quit | esc: back | enter: select | a: audit | ?: help")

	return fmt.Sprintf("%s\n%s\n%s", status, content, help)
}

func viewName(v ViewState) string {
	switch v {
	case ViewDashboard:
		return "Dashboard"
	case ViewFrameworkList:
		return "Frameworks"
	case ViewFindings:
		return "Findings"
	case ViewFindingDetail:
		return "Detail"
	case ViewAuditProgress:
		return "Audit"
	default:
		return ""
	}
}

func (m Model) navigateBack() Model {
	switch m.view {
	case ViewFindingDetail:
		m.view = ViewFindings
	case ViewFindings:
		m.view = ViewFrameworkList
	case ViewFrameworkList:
		m.view = ViewDashboard
	}
	return m
}

// Dashboard view
func (m Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, Keys.Enter):
			if m.result != nil {
				m.view = ViewFrameworkList
				m.selectedFW = 0
			}
		}
	}
	return m, nil
}

func (m Model) viewDashboard() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Okta Inspector"))
	b.WriteString("\n")

	if m.result == nil {
		b.WriteString(SubtitleStyle.Render("No audit results loaded."))
		b.WriteString("\n\nPress 'a' to run an audit, or load results from a snapshot.")
		return b.String()
	}

	b.WriteString(SubtitleStyle.Render(fmt.Sprintf("Domain: %s", m.result.Domain)))
	b.WriteString("\n\n")

	// Summary metrics
	b.WriteString(BoxStyle.Render(fmt.Sprintf(
		"Total Findings: %d    %s %d    %s %d    %s %d",
		m.result.TotalFindings,
		PassBadge.Render("PASS"), m.result.TotalPass,
		FailBadge.Render("FAIL"), m.result.TotalFail,
		ManualBadge.Render("MANUAL"), m.result.TotalManual,
	)))
	b.WriteString("\n\n")

	// Framework overview
	b.WriteString(SubtitleStyle.Render("Frameworks"))
	b.WriteString("\n")
	for _, fw := range m.result.Frameworks {
		b.WriteString(fmt.Sprintf("  %-30s  Pass: %-3d  Fail: %-3d  Manual: %-3d\n",
			fw.FrameworkName, fw.PassCount, fw.FailCount, fw.ManualCount))
	}
	b.WriteString("\n")
	b.WriteString("Press Enter to browse frameworks.")

	return b.String()
}

// Framework list view
func (m Model) updateFrameworkList(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, Keys.Up):
			if m.selectedFW > 0 {
				m.selectedFW--
			}
		case key.Matches(keyMsg, Keys.Down):
			if m.selectedFW < len(m.frameworks)-1 {
				m.selectedFW++
			}
		case key.Matches(keyMsg, Keys.Enter):
			if m.selectedFW < len(m.frameworks) {
				m.findings = m.frameworks[m.selectedFW].Findings
				m.selectedIdx = 0
				m.view = ViewFindings
			}
		}
	}
	return m, nil
}

func (m Model) viewFrameworkList() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Frameworks"))
	b.WriteString("\n\n")

	for i, fw := range m.frameworks {
		cursor := "  "
		style := NormalStyle
		if i == m.selectedFW {
			cursor = "> "
			style = SelectedStyle
		}
		line := fmt.Sprintf("%s%-30s  Pass: %-3d  Fail: %-3d  Manual: %-3d",
			cursor, fw.FrameworkName, fw.PassCount, fw.FailCount, fw.ManualCount)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}
	return b.String()
}

// Findings view
func (m Model) updateFindings(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, Keys.Up):
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case key.Matches(keyMsg, Keys.Down):
			if m.selectedIdx < len(m.findings)-1 {
				m.selectedIdx++
			}
		case key.Matches(keyMsg, Keys.Enter):
			if m.selectedIdx < len(m.findings) {
				f := m.findings[m.selectedIdx]
				m.detail = &f
				m.view = ViewFindingDetail
			}
		}
	}
	return m, nil
}

func (m Model) viewFindings() string {
	var b strings.Builder
	if m.selectedFW < len(m.frameworks) {
		b.WriteString(TitleStyle.Render(m.frameworks[m.selectedFW].FrameworkName))
	}
	b.WriteString("\n\n")

	// Show visible window of findings
	start := 0
	visible := m.height - 8
	if visible < 5 {
		visible = 20
	}
	if m.selectedIdx >= start+visible {
		start = m.selectedIdx - visible + 1
	}

	end := start + visible
	if end > len(m.findings) {
		end = len(m.findings)
	}

	for i := start; i < end; i++ {
		f := m.findings[i]
		cursor := "  "
		style := NormalStyle
		if i == m.selectedIdx {
			cursor = "> "
			style = SelectedStyle
		}
		line := fmt.Sprintf("%s%s %s [%s] %s",
			cursor, StatusBadge(string(f.Status)), SeverityBadge(string(f.Severity)),
			f.CheckID, f.Title)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("\n(%d/%d findings)", m.selectedIdx+1, len(m.findings)))
	return b.String()
}

// Finding detail view
func (m Model) viewFindingDetail() string {
	if m.detail == nil {
		return "No finding selected."
	}

	f := m.detail
	var b strings.Builder
	b.WriteString(TitleStyle.Render(fmt.Sprintf("[%s] %s", f.CheckID, f.Title)))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("Status:   %s\n", StatusBadge(string(f.Status))))
	b.WriteString(fmt.Sprintf("Severity: %s\n", SeverityBadge(string(f.Severity))))
	b.WriteString(fmt.Sprintf("Framework: %s\n\n", f.Framework))
	b.WriteString(fmt.Sprintf("Comments:\n  %s\n", f.Comments))

	if f.Remediation != "" {
		b.WriteString(fmt.Sprintf("\nRemediation:\n  %s\n", f.Remediation))
	}

	if len(f.CrossReferences) > 0 {
		b.WriteString("\nCross-References:\n")
		for fw, ctrls := range f.CrossReferences {
			b.WriteString(fmt.Sprintf("  %s: %s\n", fw, strings.Join(ctrls, ", ")))
		}
	}

	return BoxStyle.Render(b.String())
}

// Audit progress view
func (m Model) viewAuditProgress() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Running Audit"))
	b.WriteString("\n\n")
	b.WriteString(m.spinner.View())
	b.WriteString(" ")
	b.WriteString(m.progress)
	return b.String()
}
