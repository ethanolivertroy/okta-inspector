package irap

import "github.com/ethanolivertroy/okta-inspector/internal/engine"

const (
	FrameworkID   = "irap"
	FrameworkName = "IRAP (Australian ISM + Essential Eight)"
)

// Framework implements the Australian IRAP compliance checks for Okta,
// based on the Information Security Manual (ISM) and Essential Eight.
type Framework struct{}

func New() *Framework { return &Framework{} }

func (f *Framework) ID() string   { return FrameworkID }
func (f *Framework) Name() string { return FrameworkName }

func (f *Framework) Checks() []engine.Check {
	return []engine.Check{
		// Authentication
		&MFAEnforcement{},

		// Session Management
		&SessionIdleTimeout{},

		// Password Policy
		&PasswordComplexity{},

		// Account Lockout
		&AccountLockout{},

		// Logging
		&SecurityEventLogging{},

		// Privilege Management
		&RestrictAdminPrivileges{},

		// Government Domain
		&AustralianGovDomain{},
	}
}
