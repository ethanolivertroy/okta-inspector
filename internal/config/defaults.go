package config

import "time"

const (
	DefaultPageSize   = 200
	DefaultMaxPages   = 10
	DefaultTimeout    = 30 * time.Second
	DefaultOutputDir  = "okta_audit_results"
	DefaultConfigFile = "okta-inspector.yaml"
	DefaultConfigDir  = ".okta-inspector"

	EnvOktaDomain   = "OKTA_DOMAIN"
	EnvOktaAPIToken = "OKTA_API_TOKEN"
	EnvOktaOrgURL   = "OKTA_ORG_URL"

	KeyringService = "okta-inspector"
)
