package stig

import (
	"context"
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// PasswordMinLength checks V-273195: Minimum 15-character password length.
type PasswordMinLength struct{ engine.BaseCheck }

func (c *PasswordMinLength) init() {
	c.CheckID = "V-273195"
	c.CheckTitle = "Password minimum length must be at least 15 characters"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}, "irap": {"ISM-0421"}, "pcidss": {"8.3.6"}}
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
		if minLen < 15 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' requires only %d characters (min 15)", policy.Name, minLen)
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

// PasswordUppercase checks V-273196: Uppercase characters required.
type PasswordUppercase struct{ engine.BaseCheck }

func (c *PasswordUppercase) init() {
	c.CheckID = "V-273196"
	c.CheckTitle = "Password must require uppercase characters"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}}
}

func (c *PasswordUppercase) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordUppercase) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordUppercase) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordUppercase) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordUppercase) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordUppercase) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	return evalComplexityFlag(ec, &c.BaseCheck, func(complexity *complexityFlags) (bool, string) {
		return complexity.upperCase > 0, "uppercase"
	})
}

// PasswordLowercase checks V-273197: Lowercase characters required.
type PasswordLowercase struct{ engine.BaseCheck }

func (c *PasswordLowercase) init() {
	c.CheckID = "V-273197"
	c.CheckTitle = "Password must require lowercase characters"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}}
}

func (c *PasswordLowercase) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordLowercase) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordLowercase) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordLowercase) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordLowercase) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordLowercase) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	return evalComplexityFlag(ec, &c.BaseCheck, func(complexity *complexityFlags) (bool, string) {
		return complexity.lowerCase > 0, "lowercase"
	})
}

// PasswordNumber checks V-273198: Numeric characters required.
type PasswordNumber struct{ engine.BaseCheck }

func (c *PasswordNumber) init() {
	c.CheckID = "V-273198"
	c.CheckTitle = "Password must require numeric characters"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}}
}

func (c *PasswordNumber) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordNumber) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordNumber) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordNumber) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordNumber) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordNumber) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	return evalComplexityFlag(ec, &c.BaseCheck, func(complexity *complexityFlags) (bool, string) {
		return complexity.number > 0, "numeric"
	})
}

// PasswordSymbol checks V-273199: Special characters required.
type PasswordSymbol struct{ engine.BaseCheck }

func (c *PasswordSymbol) init() {
	c.CheckID = "V-273199"
	c.CheckTitle = "Password must require special characters"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}}
}

func (c *PasswordSymbol) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordSymbol) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordSymbol) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordSymbol) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordSymbol) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordSymbol) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	return evalComplexityFlag(ec, &c.BaseCheck, func(complexity *complexityFlags) (bool, string) {
		return complexity.symbol > 0, "special character"
	})
}

// PasswordMinAge checks V-273200: Minimum password age >= 24 hours (1440 minutes).
type PasswordMinAge struct{ engine.BaseCheck }

func (c *PasswordMinAge) init() {
	c.CheckID = "V-273200"
	c.CheckTitle = "Password minimum age must be at least 24 hours"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}}
}

func (c *PasswordMinAge) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordMinAge) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordMinAge) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordMinAge) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordMinAge) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordMinAge) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
		minAge := policy.Settings.Password.Age.MinAgeMinutes
		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{"policy": policy.Name, "minAgeMinutes": minAge}
		if minAge < 1440 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' has %d minute minimum age (need 1440/24h)", policy.Name, minAge)
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' has %d minute minimum age", policy.Name, minAge)
		}
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password age configuration found"))
	}
	return findings, nil
}

// PasswordMaxAge checks V-273201: Maximum password age = 60 days.
type PasswordMaxAge struct{ engine.BaseCheck }

func (c *PasswordMaxAge) init() {
	c.CheckID = "V-273201"
	c.CheckTitle = "Password maximum age must be set to 60 days"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}, "pcidss": {"8.3.9"}}
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
		if maxAge != 60 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' has %d day max age (should be 60)", policy.Name, maxAge)
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' has 60 day max age", policy.Name)
		}
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password age configuration found"))
	}
	return findings, nil
}

// PasswordCommonCheck checks V-273208: Common password dictionary check enabled.
type PasswordCommonCheck struct{ engine.BaseCheck }

func (c *PasswordCommonCheck) init() {
	c.CheckID = "V-273208"
	c.CheckTitle = "Common password check must be enabled"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}, "irap": {"ISM-0421"}}
}

func (c *PasswordCommonCheck) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordCommonCheck) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordCommonCheck) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordCommonCheck) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordCommonCheck) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordCommonCheck) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
		dict := policy.Settings.Password.Complexity.Dictionary
		enabled := dict != nil && dict.Common != nil && dict.Common.Exclude
		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{"policy": policy.Name, "dictionaryCheck": enabled}
		if !enabled {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' does not have common password check enabled", policy.Name)
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' has common password check enabled", policy.Name)
		}
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password complexity configuration found"))
	}
	return findings, nil
}

// PasswordHistory checks V-273209: Password history >= 5 generations.
type PasswordHistory struct{ engine.BaseCheck }

func (c *PasswordHistory) init() {
	c.CheckID = "V-273209"
	c.CheckTitle = "Password history must remember at least 5 passwords"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5"}, "irap": {"ISM-0421"}}
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
			f.Comments = fmt.Sprintf("Policy '%s' remembers only %d passwords (min 5)", policy.Name, history)
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

// Helpers for complexity flag checks

type complexityFlags struct {
	upperCase int
	lowerCase int
	number    int
	symbol    int
}

func evalComplexityFlag(ec *engine.EvalContext, bc *engine.BaseCheck, check func(*complexityFlags) (bool, string)) ([]engine.Finding, error) {
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Complexity == nil {
			continue
		}
		c := policy.Settings.Password.Complexity
		flags := &complexityFlags{
			upperCase: c.MinUpperCase,
			lowerCase: c.MinLowerCase,
			number:    c.MinNumber,
			symbol:    c.MinSymbol,
		}
		ok, charType := check(flags)
		f := bc.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{"policy": policy.Name}
		if !ok {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' does not require %s characters", policy.Name, charType)
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' requires %s characters", policy.Name, charType)
		}
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		findings = append(findings, bc.NewFinding(FrameworkID, engine.StatusManual, "No password complexity configuration found"))
	}
	return findings, nil
}
