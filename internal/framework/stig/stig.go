package stig

import "github.com/ethanolivertroy/okta-inspector/internal/engine"

const (
	FrameworkID   = "stig"
	FrameworkName = "DISA STIG V1R1"
)

// Framework implements the DISA STIG V1R1 compliance checks for Okta.
type Framework struct{}

func New() *Framework { return &Framework{} }

func (f *Framework) ID() string   { return FrameworkID }
func (f *Framework) Name() string { return FrameworkName }

func (f *Framework) Checks() []engine.Check {
	return []engine.Check{
		// Session Management
		&SessionIdleTimeout{},
		&AdminSessionTimeout{},
		&SessionLifetime{},
		&PersistentCookies{},

		// Authentication
		&PasswordLockout{},
		&DashboardPhishingResistant{},
		&AdminPhishingResistant{},

		// MFA
		&AdminConsoleMFA{},
		&DashboardMFA{},

		// Password Policy
		&PasswordMinLength{},
		&PasswordUppercase{},
		&PasswordLowercase{},
		&PasswordNumber{},
		&PasswordSymbol{},
		&PasswordMinAge{},
		&PasswordMaxAge{},
		&PasswordCommonCheck{},
		&PasswordHistory{},

		// Logging
		&LogOffloading{},

		// Advanced Auth
		&PIVCACSupport{},
		&FIPSCompliance{},
		&DODWarningBanner{},
	}
}
