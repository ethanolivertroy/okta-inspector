package engine

import (
	"context"
	"fmt"
	"time"
)

// ProgressFunc reports evaluation progress.
type ProgressFunc func(frameworkID string, checkIdx, totalChecks int, checkID string)

// Engine runs compliance checks across registered frameworks.
type Engine struct {
	Registry   *Registry
	OnProgress ProgressFunc
}

// NewEngine creates an engine with the given registry.
func NewEngine(reg *Registry) *Engine {
	return &Engine{Registry: reg}
}

// Evaluate runs all checks for all (or specified) frameworks against the eval context.
func (e *Engine) Evaluate(ctx context.Context, ec *EvalContext, frameworkIDs []string) (*AuditResult, error) {
	var frameworks []Framework
	if len(frameworkIDs) > 0 {
		for _, id := range frameworkIDs {
			f, ok := e.Registry.Get(id)
			if !ok {
				return nil, fmt.Errorf("unknown framework: %s", id)
			}
			frameworks = append(frameworks, f)
		}
	} else {
		frameworks = e.Registry.All()
	}

	result := &AuditResult{
		Domain:    ec.Domain,
		Timestamp: time.Now().UTC(),
	}

	for _, fw := range frameworks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		fr := FrameworkResult{
			FrameworkID:   fw.ID(),
			FrameworkName: fw.Name(),
		}

		checks := fw.Checks()
		for i, check := range checks {
			if e.OnProgress != nil {
				e.OnProgress(fw.ID(), i+1, len(checks), check.ID())
			}

			findings, err := check.Evaluate(ctx, ec)
			if err != nil {
				// Record error as a finding rather than failing the whole audit
				fr.Findings = append(fr.Findings, Finding{
					Framework: fw.ID(),
					CheckID:   check.ID(),
					Title:     check.Title(),
					Severity:  check.Severity(),
					Status:    StatusError,
					Comments:  fmt.Sprintf("Error evaluating check: %v", err),
					Timestamp: time.Now().UTC(),
				})
				continue
			}

			// Stamp metadata on findings
			for j := range findings {
				findings[j].Framework = fw.ID()
				findings[j].Timestamp = time.Now().UTC()
				if findings[j].CrossReferences == nil {
					findings[j].CrossReferences = check.CrossReferences()
				}
			}
			fr.Findings = append(fr.Findings, findings...)
		}

		result.Frameworks = append(result.Frameworks, fr)
	}

	result.Tally()
	return result, nil
}
