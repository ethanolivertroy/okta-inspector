package ismap

import "github.com/ethanolivertroy/okta-inspector/internal/engine"

const (
	FrameworkID   = "ismap"
	FrameworkName = "ISMAP (ISO 27001:2013)"
)

// Framework implements the Japanese ISMAP compliance checks for Okta,
// based on ISO 27001:2013 Annex A controls.
type Framework struct{}

func New() *Framework { return &Framework{} }

func (f *Framework) ID() string   { return FrameworkID }
func (f *Framework) Name() string { return FrameworkName }

func (f *Framework) Checks() []engine.Check {
	return []engine.Check{
		// Access Control
		&AccessControlPolicy{},
		&UserDeregistration{},
		&UserAccessProvisioning{},
		&SecretAuthInfoMgmt{},

		// Authentication
		&SecureLogOnMFA{},
		&PasswordManagement{},

		// Logging
		&EventLogging{},

		// Government Domain
		&JapaneseGovDomain{},
	}
}
