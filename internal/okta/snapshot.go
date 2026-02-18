package okta

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Snapshot holds a complete serializable tenant state.
// Fields use json.RawMessage to defer deserialization until actually needed.
type Snapshot struct {
	Domain    string    `json:"domain"`
	Collected time.Time `json:"collected"`

	// Policies
	SignOnPolicies       json.RawMessage `json:"sign_on_policies,omitempty"`
	PasswordPolicies     json.RawMessage `json:"password_policies,omitempty"`
	MFAEnrollmentPolicies json.RawMessage `json:"mfa_enrollment_policies,omitempty"`
	AccessPolicies       json.RawMessage `json:"access_policies,omitempty"`
	LifecyclePolicies    json.RawMessage `json:"lifecycle_policies,omitempty"`
	PolicyRules          map[string]json.RawMessage `json:"policy_rules,omitempty"`

	// Users and Groups
	Users  json.RawMessage `json:"users,omitempty"`
	Groups json.RawMessage `json:"groups,omitempty"`

	// Applications
	Apps json.RawMessage `json:"apps,omitempty"`

	// Authenticators
	Authenticators json.RawMessage `json:"authenticators,omitempty"`

	// Identity Providers
	IdentityProviders json.RawMessage `json:"identity_providers,omitempty"`

	// Authorization Servers
	AuthorizationServers json.RawMessage `json:"authorization_servers,omitempty"`

	// Security
	NetworkZones   json.RawMessage `json:"network_zones,omitempty"`
	TrustedOrigins json.RawMessage `json:"trusted_origins,omitempty"`
	ThreatInsight  json.RawMessage `json:"threat_insight,omitempty"`
	Behaviors      json.RawMessage `json:"behaviors,omitempty"`

	// Monitoring
	EventHooks json.RawMessage `json:"event_hooks,omitempty"`
	LogStreams json.RawMessage `json:"log_streams,omitempty"`
	SystemLogs json.RawMessage `json:"system_logs,omitempty"`

	// Additional
	Domains        json.RawMessage `json:"domains,omitempty"`
	Brands         json.RawMessage `json:"brands,omitempty"`
	OrgFactors     json.RawMessage `json:"org_factors,omitempty"`
}

// SaveToFile writes the snapshot as JSON.
func (s *Snapshot) SaveToFile(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling snapshot: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing snapshot: %w", err)
	}
	return nil
}

// LoadSnapshot reads a snapshot from a JSON file.
func LoadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing snapshot: %w", err)
	}
	return &snap, nil
}
