package engine

import "context"

// Check is the interface every compliance check must implement.
type Check interface {
	ID() string
	Title() string
	Severity() Severity
	Automated() bool
	CrossReferences() map[string][]string
	Evaluate(ctx context.Context, ec *EvalContext) ([]Finding, error)
}

// BaseCheck provides common fields for compliance checks.
// Embed this in concrete check implementations.
type BaseCheck struct {
	CheckID         string
	CheckTitle      string
	CheckSeverity   Severity
	IsAutomated     bool
	CrossRefs       map[string][]string
}

func (b *BaseCheck) ID() string                      { return b.CheckID }
func (b *BaseCheck) Title() string                   { return b.CheckTitle }
func (b *BaseCheck) Severity() Severity              { return b.CheckSeverity }
func (b *BaseCheck) Automated() bool                 { return b.IsAutomated }
func (b *BaseCheck) CrossReferences() map[string][]string { return b.CrossRefs }

// NewFinding is a helper for checks to create findings with common fields filled in.
func (b *BaseCheck) NewFinding(framework string, status Status, comments string) Finding {
	return Finding{
		Framework:       framework,
		CheckID:         b.CheckID,
		Title:           b.CheckTitle,
		Severity:        b.CheckSeverity,
		Status:          status,
		Comments:        comments,
		CrossReferences: b.CrossRefs,
	}
}
