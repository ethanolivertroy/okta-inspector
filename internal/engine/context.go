package engine

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ethanolivertroy/okta-inspector/internal/okta"
)

// EvalContext provides typed, lazy-deserialized access to snapshot data.
// Checks use this instead of accessing the snapshot directly.
type EvalContext struct {
	Snapshot *okta.Snapshot
	Domain   string

	mu    sync.Mutex
	cache map[string]any
}

// NewEvalContext creates an evaluation context from a snapshot.
func NewEvalContext(snap *okta.Snapshot, domain string) *EvalContext {
	return &EvalContext{
		Snapshot: snap,
		Domain:   domain,
		cache:    make(map[string]any),
	}
}

// decode is a generic helper that caches deserialized data.
func decode[T any](ec *EvalContext, key string, raw json.RawMessage) (T, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	if cached, ok := ec.cache[key]; ok {
		return cached.(T), nil
	}

	var result T
	if raw == nil {
		return result, fmt.Errorf("no data for %s", key)
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, fmt.Errorf("decoding %s: %w", key, err)
	}
	ec.cache[key] = result
	return result, nil
}

// Typed accessors for snapshot data.

func (ec *EvalContext) SignOnPolicies() ([]okta.Policy, error) {
	return decode[[]okta.Policy](ec, "sign_on_policies", ec.Snapshot.SignOnPolicies)
}

func (ec *EvalContext) PasswordPolicies() ([]okta.Policy, error) {
	return decode[[]okta.Policy](ec, "password_policies", ec.Snapshot.PasswordPolicies)
}

func (ec *EvalContext) MFAEnrollmentPolicies() ([]okta.Policy, error) {
	return decode[[]okta.Policy](ec, "mfa_enrollment_policies", ec.Snapshot.MFAEnrollmentPolicies)
}

func (ec *EvalContext) AccessPolicies() ([]okta.Policy, error) {
	return decode[[]okta.Policy](ec, "access_policies", ec.Snapshot.AccessPolicies)
}

func (ec *EvalContext) LifecyclePolicies() ([]okta.Policy, error) {
	return decode[[]okta.Policy](ec, "lifecycle_policies", ec.Snapshot.LifecyclePolicies)
}

func (ec *EvalContext) PolicyRules(policyID string) ([]okta.PolicyRule, error) {
	raw, ok := ec.Snapshot.PolicyRules[policyID]
	if !ok {
		return nil, nil
	}
	return decode[[]okta.PolicyRule](ec, "policy_rules_"+policyID, raw)
}

func (ec *EvalContext) Users() ([]okta.User, error) {
	return decode[[]okta.User](ec, "users", ec.Snapshot.Users)
}

func (ec *EvalContext) Groups() ([]okta.Group, error) {
	return decode[[]okta.Group](ec, "groups", ec.Snapshot.Groups)
}

func (ec *EvalContext) Apps() ([]okta.App, error) {
	return decode[[]okta.App](ec, "apps", ec.Snapshot.Apps)
}

func (ec *EvalContext) Authenticators() ([]okta.Authenticator, error) {
	return decode[[]okta.Authenticator](ec, "authenticators", ec.Snapshot.Authenticators)
}

func (ec *EvalContext) IDPs() ([]okta.IdentityProvider, error) {
	return decode[[]okta.IdentityProvider](ec, "idps", ec.Snapshot.IdentityProviders)
}

func (ec *EvalContext) NetworkZones() ([]okta.NetworkZone, error) {
	return decode[[]okta.NetworkZone](ec, "network_zones", ec.Snapshot.NetworkZones)
}

func (ec *EvalContext) TrustedOrigins() ([]okta.TrustedOrigin, error) {
	return decode[[]okta.TrustedOrigin](ec, "trusted_origins", ec.Snapshot.TrustedOrigins)
}

func (ec *EvalContext) EventHooks() ([]okta.EventHook, error) {
	return decode[[]okta.EventHook](ec, "event_hooks", ec.Snapshot.EventHooks)
}

func (ec *EvalContext) LogStreams() ([]okta.LogStream, error) {
	return decode[[]okta.LogStream](ec, "log_streams", ec.Snapshot.LogStreams)
}

func (ec *EvalContext) Behaviors() ([]okta.Behavior, error) {
	return decode[[]okta.Behavior](ec, "behaviors", ec.Snapshot.Behaviors)
}

func (ec *EvalContext) ThreatInsight() (*okta.ThreatInsight, error) {
	return decode[*okta.ThreatInsight](ec, "threat_insight", ec.Snapshot.ThreatInsight)
}

func (ec *EvalContext) AuthorizationServers() ([]okta.AuthorizationServer, error) {
	return decode[[]okta.AuthorizationServer](ec, "authorization_servers", ec.Snapshot.AuthorizationServers)
}

func (ec *EvalContext) SystemLogs() ([]okta.SystemLog, error) {
	return decode[[]okta.SystemLog](ec, "system_logs", ec.Snapshot.SystemLogs)
}

// Now returns the snapshot collection time for deterministic analysis.
// Falls back to time.Now() if the snapshot has no collection timestamp.
func (ec *EvalContext) Now() time.Time {
	if !ec.Snapshot.Collected.IsZero() {
		return ec.Snapshot.Collected
	}
	return time.Now()
}
