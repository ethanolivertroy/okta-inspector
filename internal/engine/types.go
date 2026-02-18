package engine

import "time"

// Severity levels for compliance findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status represents the outcome of a compliance check.
type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusManual        Status = "manual"
	StatusNotApplicable Status = "not_applicable"
	StatusError         Status = "error"
)

// Finding represents a single compliance evaluation result.
type Finding struct {
	Framework       string            `json:"framework"`
	CheckID         string            `json:"check_id"`
	Title           string            `json:"title"`
	Severity        Severity          `json:"severity"`
	Status          Status            `json:"status"`
	Comments        string            `json:"comments"`
	Remediation     string            `json:"remediation,omitempty"`
	Evidence        map[string]any    `json:"evidence,omitempty"`
	CrossReferences map[string][]string `json:"cross_references,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
}

// FrameworkResult groups findings for a single framework.
type FrameworkResult struct {
	FrameworkID   string    `json:"framework_id"`
	FrameworkName string    `json:"framework_name"`
	Findings      []Finding `json:"findings"`
	PassCount     int       `json:"pass_count"`
	FailCount     int       `json:"fail_count"`
	ManualCount   int       `json:"manual_count"`
	ErrorCount    int       `json:"error_count"`
}

// Tally recomputes the counts from findings.
func (fr *FrameworkResult) Tally() {
	fr.PassCount = 0
	fr.FailCount = 0
	fr.ManualCount = 0
	fr.ErrorCount = 0
	for _, f := range fr.Findings {
		switch f.Status {
		case StatusPass:
			fr.PassCount++
		case StatusFail:
			fr.FailCount++
		case StatusManual:
			fr.ManualCount++
		case StatusError:
			fr.ErrorCount++
		}
	}
}

// AuditResult is the complete output of a compliance audit.
type AuditResult struct {
	Domain          string            `json:"domain"`
	Timestamp       time.Time         `json:"timestamp"`
	Frameworks      []FrameworkResult `json:"frameworks"`
	TotalFindings   int               `json:"total_findings"`
	TotalPass       int               `json:"total_pass"`
	TotalFail       int               `json:"total_fail"`
	TotalManual     int               `json:"total_manual"`
	APICallCount    int               `json:"api_call_count"`
}

// Tally recomputes the totals from framework results.
func (ar *AuditResult) Tally() {
	ar.TotalFindings = 0
	ar.TotalPass = 0
	ar.TotalFail = 0
	ar.TotalManual = 0
	for i := range ar.Frameworks {
		ar.Frameworks[i].Tally()
		ar.TotalFindings += len(ar.Frameworks[i].Findings)
		ar.TotalPass += ar.Frameworks[i].PassCount
		ar.TotalFail += ar.Frameworks[i].FailCount
		ar.TotalManual += ar.Frameworks[i].ManualCount
	}
}
