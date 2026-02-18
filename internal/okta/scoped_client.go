package okta

import (
	"context"
	"fmt"
)

// ErrCapabilityDenied is returned when an operation is blocked by capability restrictions.
type ErrCapabilityDenied struct {
	Scope string
}

func (e *ErrCapabilityDenied) Error() string {
	return fmt.Sprintf("capability denied: scope %q not allowed", e.Scope)
}

// ScopedClient wraps a Client and restricts API access based on allowed scopes.
type ScopedClient struct {
	Inner  *Client
	Scopes map[string]bool
}

// NewScopedClient creates a capability-restricted wrapper around a Client.
func NewScopedClient(inner *Client, scopes []string) *ScopedClient {
	scopeMap := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		scopeMap[s] = true
	}
	return &ScopedClient{Inner: inner, Scopes: scopeMap}
}

// HasScope checks if a scope is allowed.
func (s *ScopedClient) HasScope(scope string) bool {
	return s.Scopes[scope]
}

// CollectSnapshot collects data but only for allowed scopes.
func (s *ScopedClient) CollectSnapshot(ctx context.Context, domain string) (*Snapshot, error) {
	// Delegate to inner client — the snapshot fields for disallowed scopes will be nil.
	// The engine checks will handle nil gracefully.
	// For stricter enforcement, you could zero out disallowed fields after collection.
	snap, err := s.Inner.CollectSnapshot(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Zero out fields for disallowed scopes
	if !s.Scopes["policies:read"] {
		snap.SignOnPolicies = nil
		snap.PasswordPolicies = nil
		snap.MFAEnrollmentPolicies = nil
		snap.AccessPolicies = nil
		snap.LifecyclePolicies = nil
		snap.PolicyRules = nil
	}
	if !s.Scopes["users:read"] {
		snap.Users = nil
		snap.Groups = nil
	}
	if !s.Scopes["apps:read"] {
		snap.Apps = nil
	}
	if !s.Scopes["authenticators:read"] {
		snap.Authenticators = nil
	}
	if !s.Scopes["logs:read"] {
		snap.SystemLogs = nil
		snap.EventHooks = nil
		snap.LogStreams = nil
	}

	return snap, nil
}
