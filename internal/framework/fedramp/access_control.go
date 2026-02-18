package fedramp

import (
	"context"
	"fmt"
	"time"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// InactiveAccounts checks AC-2: Accounts inactive for 90+ days must be identified.
type InactiveAccounts struct {
	engine.BaseCheck
}

func (c *InactiveAccounts) init() {
	c.CheckID = "AC-2"
	c.CheckTitle = "Inactive accounts (90+ days) must be disabled or removed"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273188"},
		"soc2": {"CC6.1"},
	}
}

func (c *InactiveAccounts) ID() string                           { c.init(); return c.CheckID }
func (c *InactiveAccounts) Title() string                        { c.init(); return c.CheckTitle }
func (c *InactiveAccounts) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *InactiveAccounts) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *InactiveAccounts) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *InactiveAccounts) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	users, err := ec.Users()
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().AddDate(0, 0, -90)
	var findings []engine.Finding
	inactiveCount := 0

	for _, user := range users {
		if user.Status == "DEPROVISIONED" || user.Status == "SUSPENDED" {
			continue
		}
		if user.LastLogin == nil || user.LastLogin.Before(cutoff) {
			inactiveCount++
			loginStr := "never"
			if user.LastLogin != nil {
				loginStr = user.LastLogin.Format("2006-01-02")
			}
			findings = append(findings, engine.Finding{
				CheckID:  c.CheckID,
				Title:    c.CheckTitle,
				Severity: c.CheckSeverity,
				Status:   engine.StatusFail,
				Comments: fmt.Sprintf("User '%s' last login: %s (inactive 90+ days)", user.Profile.Login, loginStr),
				Evidence: map[string]any{
					"user":      user.Profile.Login,
					"lastLogin": loginStr,
					"status":    user.Status,
				},
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if inactiveCount == 0 {
		findings = append(findings, engine.Finding{
			CheckID:         c.CheckID,
			Title:           c.CheckTitle,
			Severity:        c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        "No active accounts found with 90+ days of inactivity",
			CrossReferences: c.CrossRefs,
		})
	}
	return findings, nil
}

// AccountLockout checks AC-7: Account lockout must be <= 6 attempts.
type AccountLockout struct {
	engine.BaseCheck
}

func (c *AccountLockout) init() {
	c.CheckID = "AC-7"
	c.CheckTitle = "Account lockout must be enforced after no more than 6 failed attempts"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":  {"V-273189"},
		"irap":  {"ISM-1173"},
		"pcidss": {"8.2.6"},
	}
}

func (c *AccountLockout) ID() string                           { c.init(); return c.CheckID }
func (c *AccountLockout) Title() string                        { c.init(); return c.CheckTitle }
func (c *AccountLockout) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AccountLockout) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AccountLockout) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AccountLockout) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Lockout == nil {
			continue
		}
		lockout := policy.Settings.Password.Lockout
		if lockout.MaxAttempts > 6 || lockout.MaxAttempts == 0 {
			findings = append(findings, engine.Finding{
				CheckID:  c.CheckID,
				Title:    c.CheckTitle,
				Severity: c.CheckSeverity,
				Status:   engine.StatusFail,
				Comments: fmt.Sprintf("Policy '%s' allows %d attempts before lockout (max 6)", policy.Name, lockout.MaxAttempts),
				Evidence: map[string]any{
					"policy":      policy.Name,
					"maxAttempts": lockout.MaxAttempts,
				},
				CrossReferences: c.CrossRefs,
			})
		} else {
			findings = append(findings, engine.Finding{
				CheckID:  c.CheckID,
				Title:    c.CheckTitle,
				Severity: c.CheckSeverity,
				Status:   engine.StatusPass,
				Comments: fmt.Sprintf("Policy '%s' locks out after %d attempts", policy.Name, lockout.MaxAttempts),
				Evidence: map[string]any{
					"policy":      policy.Name,
					"maxAttempts": lockout.MaxAttempts,
				},
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with lockout configuration found"))
	}
	return findings, nil
}

// WarningBanner checks AC-8: System use notification/warning banner must be displayed.
type WarningBanner struct {
	engine.BaseCheck
}

func (c *WarningBanner) init() {
	c.CheckID = "AC-8"
	c.CheckTitle = "System use notification (warning banner) must be displayed before login"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = false
	c.CrossRefs = map[string][]string{
		"stig": {"V-273192"},
	}
}

func (c *WarningBanner) ID() string                           { c.init(); return c.CheckID }
func (c *WarningBanner) Title() string                        { c.init(); return c.CheckTitle }
func (c *WarningBanner) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *WarningBanner) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *WarningBanner) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *WarningBanner) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
		"Warning banner requires UI verification; check custom sign-in page for appropriate system use notification text")}, nil
}

// SessionIdleTimeout checks AC-11: Session idle timeout must be configured.
type SessionIdleTimeout struct {
	engine.BaseCheck
}

func (c *SessionIdleTimeout) init() {
	c.CheckID = "AC-11"
	c.CheckTitle = "Session idle timeout must be configured to lock sessions after inactivity"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":  {"V-273186", "V-273187"},
		"irap":  {"ISM-1546"},
		"ismap": {"A.9.4.2"},
		"soc2":  {"CC6.6"},
	}
}

func (c *SessionIdleTimeout) ID() string                           { c.init(); return c.CheckID }
func (c *SessionIdleTimeout) Title() string                        { c.init(); return c.CheckTitle }
func (c *SessionIdleTimeout) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SessionIdleTimeout) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SessionIdleTimeout) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SessionIdleTimeout) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.SignOnPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil || rule.Actions.SignOn.Session == nil {
				continue
			}
			idle := rule.Actions.SignOn.Session.MaxSessionIdleMinutes
			if idle > 15 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout (max 15)", policy.Name, rule.Name, idle),
					Evidence: map[string]any{
						"policy":  policy.Name,
						"rule":    rule.Name,
						"timeout": idle,
					},
					CrossReferences: c.CrossRefs,
				})
			} else if idle > 0 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout", policy.Name, rule.Name, idle),
					Evidence: map[string]any{
						"policy":  policy.Name,
						"rule":    rule.Name,
						"timeout": idle,
					},
					CrossReferences: c.CrossRefs,
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No sign-on policy rules with session idle timeout found"))
	}
	return findings, nil
}

// SessionLifetime checks AC-12: Session lifetime must be configured.
type SessionLifetime struct {
	engine.BaseCheck
}

func (c *SessionLifetime) init() {
	c.CheckID = "AC-12"
	c.CheckTitle = "Session lifetime must be limited and sessions terminated after defined conditions"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273203", "V-273206"},
		"irap": {"ISM-1546"},
	}
}

func (c *SessionLifetime) ID() string                           { c.init(); return c.CheckID }
func (c *SessionLifetime) Title() string                        { c.init(); return c.CheckTitle }
func (c *SessionLifetime) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SessionLifetime) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SessionLifetime) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SessionLifetime) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.SignOnPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil || rule.Actions.SignOn.Session == nil {
				continue
			}
			sess := rule.Actions.SignOn.Session
			lifetime := sess.MaxSessionLifetimeMinutes
			if lifetime > 480 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %.1f hour session lifetime (max 8 hours recommended)", policy.Name, rule.Name, float64(lifetime)/60),
					Evidence: map[string]any{
						"policy":           policy.Name,
						"rule":             rule.Name,
						"lifetime_minutes": lifetime,
					},
					CrossReferences: c.CrossRefs,
				})
			} else if lifetime > 0 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %.1f hour session lifetime", policy.Name, rule.Name, float64(lifetime)/60),
					Evidence: map[string]any{
						"policy":           policy.Name,
						"rule":             rule.Name,
						"lifetime_minutes": lifetime,
					},
					CrossReferences: c.CrossRefs,
				})
			}

			// Also check persistent cookies per AC-12
			if sess.UsePersistentCookie {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has persistent cookies enabled (sessions should terminate properly)", policy.Name, rule.Name),
					Evidence: map[string]any{
						"policy":           policy.Name,
						"rule":             rule.Name,
						"persistentCookie": true,
					},
					CrossReferences: c.CrossRefs,
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No session lifetime configuration found"))
	}
	return findings, nil
}
