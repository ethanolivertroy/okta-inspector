package pcidss

import "github.com/ethanolivertroy/okta-inspector/internal/engine"

const (
	FrameworkID   = "pcidss"
	FrameworkName = "PCI-DSS 4.0"
)

// Framework implements the PCI-DSS 4.0 compliance checks for Okta.
type Framework struct{}

func New() *Framework { return &Framework{} }

func (f *Framework) ID() string   { return FrameworkID }
func (f *Framework) Name() string { return FrameworkName }

func (f *Framework) Checks() []engine.Check {
	return []engine.Check{
		// 7.2.1: Role-based access control
		&RBACGroups{},

		// 8.2.1: Strong authentication methods
		&StrongAuthentication{},

		// 8.2.6: Account lockout
		&AccountLockout{},

		// 8.2.8: Session idle timeout
		&SessionIdleTimeout{},

		// 8.3.1: MFA enforcement
		&MFAEnforcement{},

		// 8.3.6: Password minimum length and complexity
		&PasswordComplexity{},

		// 8.3.9: Password rotation
		&PasswordRotation{},
	}
}
