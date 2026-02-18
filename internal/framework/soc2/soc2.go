package soc2

import "github.com/ethanolivertroy/okta-inspector/internal/engine"

const (
	FrameworkID   = "soc2"
	FrameworkName = "SOC 2 Trust Service Criteria"
)

// Framework implements the SOC 2 Trust Service Criteria compliance checks for Okta.
type Framework struct{}

func New() *Framework { return &Framework{} }

func (f *Framework) ID() string   { return FrameworkID }
func (f *Framework) Name() string { return FrameworkName }

func (f *Framework) Checks() []engine.Check {
	return []engine.Check{
		// CC6.1: Logical access controls with MFA
		&LogicalAccessMFA{},

		// CC6.2: User lifecycle management
		&UserLifecycleManagement{},

		// CC6.3: Role-based access control
		&RoleBasedAccessControl{},

		// CC6.6: Session security
		&SessionSecurity{},

		// CC6.7: Trusted origins for secure transmission
		&TrustedOriginsCheck{},

		// CC6.8: Unauthorized access prevention
		&UnauthorizedAccessPrevention{},
	}
}
