package fedramp

import "github.com/ethanolivertroy/okta-inspector/internal/engine"

const (
	FrameworkID   = "fedramp"
	FrameworkName = "FedRAMP (NIST 800-53)"
)

// Framework implements the FedRAMP (NIST 800-53) compliance checks for Okta.
type Framework struct{}

func New() *Framework { return &Framework{} }

func (f *Framework) ID() string   { return FrameworkID }
func (f *Framework) Name() string { return FrameworkName }

func (f *Framework) Checks() []engine.Check {
	return []engine.Check{
		// Access Control (AC)
		&InactiveAccounts{},
		&AccountLockout{},
		&WarningBanner{},
		&SessionIdleTimeout{},
		&SessionLifetime{},

		// Audit and Accountability (AU)
		&AuditableEvents{},
		&AuditContent{},
		&LogOffloading{},
		&AuditReview{},

		// Identification and Authentication (IA)
		&MFAEnforcement{},
		&PasswordMinLength{},
		&PasswordComplexity{},
		&PasswordMaxAge{},
		&PasswordHistory{},

		// System and Communications Protection (SC)
		&FIPSMode{},

		// System and Information Integrity (SI)
		&ThreatInsightDetection{},
		&BehaviorDetection{},
	}
}
