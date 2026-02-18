package fedramp

import (
	"context"
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// MFAEnforcement checks IA-2: Multi-factor authentication must be enforced.
type MFAEnforcement struct {
	engine.BaseCheck
}

func (c *MFAEnforcement) init() {
	c.CheckID = "IA-2"
	c.CheckTitle = "Multi-factor authentication must be enforced for all users"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":  {"V-273193", "V-273194"},
		"irap":  {"ISM-0974"},
		"soc2":  {"CC6.1"},
		"pcidss": {"8.3.1"},
	}
}

func (c *MFAEnforcement) ID() string                           { c.init(); return c.CheckID }
func (c *MFAEnforcement) Title() string                        { c.init(); return c.CheckTitle }
func (c *MFAEnforcement) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *MFAEnforcement) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *MFAEnforcement) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *MFAEnforcement) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()

	// Check authenticators for active MFA methods
	authenticators, err := ec.Authenticators()
	if err != nil {
		return nil, err
	}

	activeMFA := 0
	var mfaNames []string
	for _, auth := range authenticators {
		if auth.Status == "ACTIVE" && isMFAAuthenticator(auth.Key) {
			activeMFA++
			mfaNames = append(mfaNames, auth.Name)
		}
	}

	var findings []engine.Finding

	if activeMFA == 0 {
		findings = append(findings, engine.Finding{
			CheckID:     c.CheckID,
			Title:       c.CheckTitle,
			Severity:    c.CheckSeverity,
			Status:      engine.StatusFail,
			Comments:    "No active MFA authenticators found",
			Remediation: "Enable at least one MFA authenticator (Okta Verify, FIDO2/WebAuthn, etc.) and enforce MFA in sign-on policies",
			CrossReferences: c.CrossRefs,
		})
		return findings, nil
	}

	findings = append(findings, engine.Finding{
		CheckID:  c.CheckID,
		Title:    c.CheckTitle,
		Severity: c.CheckSeverity,
		Status:   engine.StatusPass,
		Comments: fmt.Sprintf("%d active MFA authenticator(s) found; verify MFA is required in all sign-on policy rules", activeMFA),
		Evidence: map[string]any{
			"activeMFACount":  activeMFA,
			"authenticators":  mfaNames,
		},
		CrossReferences: c.CrossRefs,
	})

	// Additionally check sign-on policies for MFA enforcement
	policies, _ := ec.SignOnPolicies()
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil {
				continue
			}
			if rule.Actions.SignOn.FactorMode == "1FA" {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' allows single-factor authentication", policy.Name, rule.Name),
					Evidence: map[string]any{
						"policy":     policy.Name,
						"rule":       rule.Name,
						"factorMode": rule.Actions.SignOn.FactorMode,
					},
					CrossReferences: c.CrossRefs,
				})
			}
		}
	}

	return findings, nil
}

func isMFAAuthenticator(key string) bool {
	switch key {
	case "okta_verify", "google_otp", "phone_number", "security_question",
		"webauthn", "fido2", "smart_card_idp", "duo", "symantec_vip",
		"yubikey_token", "okta_email", "external_idp":
		return true
	}
	return false
}

// PasswordMinLength checks IA-5 (password length): Minimum password length must be >= 12 characters.
type PasswordMinLength struct {
	engine.BaseCheck
}

func (c *PasswordMinLength) init() {
	c.CheckID = "IA-5(len)"
	c.CheckTitle = "Password minimum length must be at least 12 characters"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":  {"V-273195"},
		"irap":  {"ISM-0421"},
		"pcidss": {"8.3.6"},
	}
}

func (c *PasswordMinLength) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordMinLength) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordMinLength) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordMinLength) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordMinLength) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordMinLength) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
		minLen := policy.Settings.Password.Complexity.MinLength
		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{"policy": policy.Name, "minLength": minLen}
		if minLen < 12 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' requires only %d characters (min 12)", policy.Name, minLen)
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' requires %d characters", policy.Name, minLen)
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies found"))
	}
	return findings, nil
}

// PasswordComplexity checks IA-5 (complexity): Passwords must require mixed case, numbers, and symbols.
type PasswordComplexity struct {
	engine.BaseCheck
}

func (c *PasswordComplexity) init() {
	c.CheckID = "IA-5(complex)"
	c.CheckTitle = "Passwords must require uppercase, lowercase, numeric, and special characters"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273196", "V-273197", "V-273198", "V-273199"},
	}
}

func (c *PasswordComplexity) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordComplexity) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordComplexity) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordComplexity) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordComplexity) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordComplexity) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
		var missing []string
		if comp.MinUpperCase < 1 {
			missing = append(missing, "uppercase")
		}
		if comp.MinLowerCase < 1 {
			missing = append(missing, "lowercase")
		}
		if comp.MinNumber < 1 {
			missing = append(missing, "numeric")
		}
		if comp.MinSymbol < 1 {
			missing = append(missing, "special character")
		}

		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{
			"policy":       policy.Name,
			"minUpperCase": comp.MinUpperCase,
			"minLowerCase": comp.MinLowerCase,
			"minNumber":    comp.MinNumber,
			"minSymbol":    comp.MinSymbol,
		}

		if len(missing) > 0 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' does not require: %s", policy.Name, joinStrings(missing))
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' requires all character types (uppercase, lowercase, numeric, special)", policy.Name)
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password complexity configuration found"))
	}
	return findings, nil
}

// PasswordMaxAge checks IA-5 (age): Password maximum age must be configured.
type PasswordMaxAge struct {
	engine.BaseCheck
}

func (c *PasswordMaxAge) init() {
	c.CheckID = "IA-5(age)"
	c.CheckTitle = "Password maximum age must be configured (60 days recommended)"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":  {"V-273201"},
		"pcidss": {"8.3.9"},
	}
}

func (c *PasswordMaxAge) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordMaxAge) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordMaxAge) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordMaxAge) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordMaxAge) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordMaxAge) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Age == nil {
			continue
		}
		maxAge := policy.Settings.Password.Age.MaxAgeDays
		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{"policy": policy.Name, "maxAgeDays": maxAge}
		if maxAge == 0 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' has no password expiration configured", policy.Name)
		} else if maxAge > 60 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' has %d day max age (recommended 60 days or less)", policy.Name, maxAge)
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' has %d day max age", policy.Name, maxAge)
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password age configuration found"))
	}
	return findings, nil
}

// PasswordHistory checks IA-5 (history): Password history must prevent reuse.
type PasswordHistory struct {
	engine.BaseCheck
}

func (c *PasswordHistory) init() {
	c.CheckID = "IA-5(hist)"
	c.CheckTitle = "Password history must prevent reuse of recent passwords"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273209"},
		"irap": {"ISM-0421"},
	}
}

func (c *PasswordHistory) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordHistory) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordHistory) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordHistory) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordHistory) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordHistory) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Age == nil {
			continue
		}
		history := policy.Settings.Password.Age.HistoryCount
		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{"policy": policy.Name, "historyCount": history}
		if history < 5 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' remembers only %d passwords (min 5 recommended)", policy.Name, history)
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' remembers %d passwords", policy.Name, history)
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password history configuration found"))
	}
	return findings, nil
}

// joinStrings joins string slice with comma separator.
func joinStrings(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}
