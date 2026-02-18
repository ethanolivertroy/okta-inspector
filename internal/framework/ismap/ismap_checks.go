package ismap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// AccessControlPolicy checks A.9.1.1: An access control policy must be established.
type AccessControlPolicy struct{ engine.BaseCheck }

func (c *AccessControlPolicy) init() {
	c.CheckID = "A.9.1.1"
	c.CheckTitle = "Access control policy must be established"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AC-1"},
		"irap":    {"ISM-0974"},
	}
}

func (c *AccessControlPolicy) ID() string                           { c.init(); return c.CheckID }
func (c *AccessControlPolicy) Title() string                        { c.init(); return c.CheckTitle }
func (c *AccessControlPolicy) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AccessControlPolicy) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AccessControlPolicy) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AccessControlPolicy) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.AccessPolicies()
	if err != nil {
		return nil, err
	}

	if len(policies) > 0 {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Found %d access policies established", len(policies)),
			Evidence: map[string]any{"policyCount": len(policies)},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    "No access control policies found",
		Remediation: "Establish access control policies to govern user access to Okta resources",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// UserDeregistration checks A.9.2.1: Inactive users (90+ days without login)
// must be identified for de-registration.
type UserDeregistration struct{ engine.BaseCheck }

func (c *UserDeregistration) init() {
	c.CheckID = "A.9.2.1"
	c.CheckTitle = "Inactive users (90+ days) must be identified for de-registration"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AC-2"},
		"irap":    {"ISM-1175"},
	}
}

func (c *UserDeregistration) ID() string                           { c.init(); return c.CheckID }
func (c *UserDeregistration) Title() string                        { c.init(); return c.CheckTitle }
func (c *UserDeregistration) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *UserDeregistration) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *UserDeregistration) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *UserDeregistration) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	users, err := ec.Users()
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().AddDate(0, 0, -90)
	inactiveCount := 0
	totalActive := 0

	for _, user := range users {
		if user.Status != "ACTIVE" {
			continue
		}
		totalActive++
		if user.LastLogin == nil || user.LastLogin.Before(cutoff) {
			inactiveCount++
		}
	}

	if inactiveCount > 0 {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusFail,
			Comments: fmt.Sprintf("Found %d active users with no login in 90+ days (of %d active users)", inactiveCount, totalActive),
			Evidence: map[string]any{
				"inactiveUsers": inactiveCount,
				"totalActive":   totalActive,
				"cutoffDays":    90,
			},
			Remediation:     "Review and de-register or deactivate users who have not logged in for 90+ days",
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	if totalActive == 0 {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual, "No active users found to evaluate")}, nil
	}

	return []engine.Finding{{
		CheckID:  c.CheckID,
		Title:    c.CheckTitle,
		Severity: c.CheckSeverity,
		Status:   engine.StatusPass,
		Comments: fmt.Sprintf("All %d active users have logged in within the last 90 days", totalActive),
		Evidence: map[string]any{"totalActive": totalActive},
		CrossReferences: c.CrossRefs,
	}}, nil
}

// UserAccessProvisioning checks A.9.2.2: Groups must exist for formal user access
// provisioning and management.
type UserAccessProvisioning struct{ engine.BaseCheck }

func (c *UserAccessProvisioning) init() {
	c.CheckID = "A.9.2.2"
	c.CheckTitle = "Groups must exist for formal user access provisioning"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AC-2"},
		"irap":    {"ISM-1175"},
	}
}

func (c *UserAccessProvisioning) ID() string                           { c.init(); return c.CheckID }
func (c *UserAccessProvisioning) Title() string                        { c.init(); return c.CheckTitle }
func (c *UserAccessProvisioning) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *UserAccessProvisioning) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *UserAccessProvisioning) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *UserAccessProvisioning) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	groups, err := ec.Groups()
	if err != nil {
		return nil, err
	}

	if len(groups) > 0 {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Found %d groups for access management", len(groups)),
			Evidence: map[string]any{"groupCount": len(groups)},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    "No groups found for access management",
		Remediation: "Create groups to manage user access provisioning in accordance with ISO 27001 A.9.2.2",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// SecretAuthInfoMgmt checks A.9.2.4: Password minimum length >= 8 with complexity.
type SecretAuthInfoMgmt struct{ engine.BaseCheck }

func (c *SecretAuthInfoMgmt) init() {
	c.CheckID = "A.9.2.4"
	c.CheckTitle = "Secret authentication information must be managed (password min length >= 8 + complexity)"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"IA-5"},
		"irap":    {"ISM-0421"},
		"stig":    {"V-273195"},
	}
}

func (c *SecretAuthInfoMgmt) ID() string                           { c.init(); return c.CheckID }
func (c *SecretAuthInfoMgmt) Title() string                        { c.init(); return c.CheckTitle }
func (c *SecretAuthInfoMgmt) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SecretAuthInfoMgmt) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SecretAuthInfoMgmt) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SecretAuthInfoMgmt) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Complexity == nil {
			continue
		}
		comp := policy.Settings.Password.Complexity
		var failures []string

		if comp.MinLength < 8 {
			failures = append(failures, fmt.Sprintf("minLength=%d (need 8)", comp.MinLength))
		}
		if comp.MinUpperCase < 1 {
			failures = append(failures, "uppercase not required")
		}
		if comp.MinLowerCase < 1 {
			failures = append(failures, "lowercase not required")
		}
		if comp.MinNumber < 1 {
			failures = append(failures, "number not required")
		}
		if comp.MinSymbol < 1 {
			failures = append(failures, "symbol not required")
		}

		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{
			"policy":    policy.Name,
			"minLength": comp.MinLength,
			"upper":     comp.MinUpperCase,
			"lower":     comp.MinLowerCase,
			"number":    comp.MinNumber,
			"symbol":    comp.MinSymbol,
		}

		if len(failures) > 0 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' does not meet ISMAP password requirements: %s", policy.Name, strings.Join(failures, "; "))
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' meets ISMAP password complexity requirements", policy.Name)
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with complexity settings found"))
	}
	return findings, nil
}

// SecureLogOnMFA checks A.9.4.2: Secure log-on procedures must include MFA.
type SecureLogOnMFA struct{ engine.BaseCheck }

func (c *SecureLogOnMFA) init() {
	c.CheckID = "A.9.4.2"
	c.CheckTitle = "Secure log-on procedures must require MFA"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"IA-2"},
		"irap":    {"ISM-0974"},
		"stig":    {"V-273193", "V-273194"},
		"pcidss":  {"8.3.1"},
	}
}

func (c *SecureLogOnMFA) ID() string                           { c.init(); return c.CheckID }
func (c *SecureLogOnMFA) Title() string                        { c.init(); return c.CheckTitle }
func (c *SecureLogOnMFA) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SecureLogOnMFA) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SecureLogOnMFA) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SecureLogOnMFA) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.AccessPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		hasMFARule := false
		for _, rule := range rules {
			if rule.Actions != nil && rule.Actions.SignOn != nil &&
				rule.Actions.SignOn.FactorMode != "" &&
				rule.Actions.SignOn.FactorMode != "1FA" {
				hasMFARule = true
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' requires MFA (factorMode=%s)", policy.Name, rule.Name, rule.Actions.SignOn.FactorMode),
					Evidence: map[string]any{"policy": policy.Name, "rule": rule.Name, "factorMode": rule.Actions.SignOn.FactorMode},
					CrossReferences: c.CrossRefs,
				})
			}
		}
		if !hasMFARule && len(rules) > 0 {
			findings = append(findings, engine.Finding{
				CheckID:  c.CheckID,
				Title:    c.CheckTitle,
				Severity: c.CheckSeverity,
				Status:   engine.StatusFail,
				Comments: fmt.Sprintf("Policy '%s' has no rules requiring MFA for secure log-on", policy.Name),
				Evidence: map[string]any{"policy": policy.Name},
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No access policies found; verify MFA enforcement manually"))
	}
	return findings, nil
}

// PasswordManagement checks A.9.4.3: Password lockout <= 5 attempts and history >= 3.
type PasswordManagement struct{ engine.BaseCheck }

func (c *PasswordManagement) init() {
	c.CheckID = "A.9.4.3"
	c.CheckTitle = "Password management must enforce lockout (<= 5 attempts) and history (>= 3)"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AC-7", "IA-5"},
		"irap":    {"ISM-1173"},
		"stig":    {"V-273189", "V-273209"},
	}
}

func (c *PasswordManagement) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordManagement) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordManagement) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordManagement) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordManagement) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordManagement) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil {
			continue
		}

		// Check lockout
		if policy.Settings.Password.Lockout != nil {
			lockout := policy.Settings.Password.Lockout
			if lockout.MaxAttempts > 5 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' allows %d attempts before lockout (max 5)", policy.Name, lockout.MaxAttempts),
					Evidence: map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts, "aspect": "lockout"},
					CrossReferences: c.CrossRefs,
				})
			} else {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' locks after %d attempts", policy.Name, lockout.MaxAttempts),
					Evidence: map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts, "aspect": "lockout"},
					CrossReferences: c.CrossRefs,
				})
			}
		}

		// Check history
		if policy.Settings.Password.Age != nil {
			history := policy.Settings.Password.Age.HistoryCount
			if history < 3 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' remembers only %d passwords (min 3)", policy.Name, history),
					Evidence: map[string]any{"policy": policy.Name, "historyCount": history, "aspect": "history"},
					CrossReferences: c.CrossRefs,
				})
			} else {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' remembers %d passwords", policy.Name, history),
					Evidence: map[string]any{"policy": policy.Name, "historyCount": history, "aspect": "history"},
					CrossReferences: c.CrossRefs,
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with lockout or history configuration found"))
	}
	return findings, nil
}

// EventLogging checks A.12.4.1: Event logging must be configured via log streams.
type EventLogging struct{ engine.BaseCheck }

func (c *EventLogging) init() {
	c.CheckID = "A.12.4.1"
	c.CheckTitle = "Event logging must be configured"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AU-4", "AU-6"},
		"irap":    {"ISM-0407"},
		"stig":    {"V-273202"},
	}
}

func (c *EventLogging) ID() string                           { c.init(); return c.CheckID }
func (c *EventLogging) Title() string                        { c.init(); return c.CheckTitle }
func (c *EventLogging) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *EventLogging) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *EventLogging) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *EventLogging) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()

	logStreams, _ := ec.LogStreams()

	activeStreams := 0
	for _, s := range logStreams {
		if s.Status == "ACTIVE" {
			activeStreams++
		}
	}

	if activeStreams > 0 {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Event logging configured with %d active log streams", activeStreams),
			Evidence: map[string]any{"activeStreams": activeStreams},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    "No active log streams found for event logging",
		Remediation: "Configure at least one log stream for event logging per ISO 27001 A.12.4.1",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// JapaneseGovDomain checks ISMAP-GOV: Okta domain should use .go.jp for
// Japanese government deployments.
type JapaneseGovDomain struct{ engine.BaseCheck }

func (c *JapaneseGovDomain) init() {
	c.CheckID = "ISMAP-GOV"
	c.CheckTitle = "Okta domain should use Japanese government domain (.go.jp)"
	c.CheckSeverity = engine.SeverityLow
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{}
}

func (c *JapaneseGovDomain) ID() string                           { c.init(); return c.CheckID }
func (c *JapaneseGovDomain) Title() string                        { c.init(); return c.CheckTitle }
func (c *JapaneseGovDomain) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *JapaneseGovDomain) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *JapaneseGovDomain) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *JapaneseGovDomain) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	domain := ec.Domain

	if strings.HasSuffix(domain, ".go.jp") || strings.Contains(domain, ".go.jp.") {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Domain '%s' is a Japanese government domain", domain),
			Evidence: map[string]any{"domain": domain},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    fmt.Sprintf("Domain '%s' is not a Japanese government domain (.go.jp)", domain),
		Evidence:    map[string]any{"domain": domain},
		Remediation: "For Japanese government deployments, use a .go.jp domain for the Okta tenant",
		CrossReferences: c.CrossRefs,
	}}, nil
}
