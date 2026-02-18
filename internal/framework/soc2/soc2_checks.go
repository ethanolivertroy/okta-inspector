package soc2

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// ---------------------------------------------------------------------------
// CC6.1: Logical access controls with MFA
// ---------------------------------------------------------------------------

// LogicalAccessMFA checks CC6.1: Logical access controls require strong MFA methods.
type LogicalAccessMFA struct {
	engine.BaseCheck
}

func (c *LogicalAccessMFA) init() {
	c.CheckID = "CC6.1"
	c.CheckTitle = "Logical access controls must enforce MFA with strong authenticators"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":   {"V-273194"},
		"pcidss": {"8.3.1"},
	}
}

func (c *LogicalAccessMFA) ID() string                           { c.init(); return c.CheckID }
func (c *LogicalAccessMFA) Title() string                        { c.init(); return c.CheckTitle }
func (c *LogicalAccessMFA) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *LogicalAccessMFA) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *LogicalAccessMFA) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *LogicalAccessMFA) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	authenticators, err := ec.Authenticators()
	if err != nil {
		return nil, err
	}

	strongMethods := []string{"okta_verify", "webauthn", "fido2"}
	var activeStrong []string
	for _, auth := range authenticators {
		if auth.Status != "ACTIVE" {
			continue
		}
		for _, method := range strongMethods {
			if auth.Key == method {
				activeStrong = append(activeStrong, auth.Name)
			}
		}
	}

	if len(activeStrong) > 0 {
		return []engine.Finding{{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        fmt.Sprintf("Strong MFA authenticators active: %s", strings.Join(activeStrong, ", ")),
			Evidence:        map[string]any{"activeStrong": activeStrong},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
		Status:          engine.StatusFail,
		Comments:        "No strong MFA authenticators found active (require okta_verify, webauthn, or fido2)",
		Remediation:     "Enable at least one strong authenticator: Okta Verify, WebAuthn, or FIDO2",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// ---------------------------------------------------------------------------
// CC6.2: User lifecycle management
// ---------------------------------------------------------------------------

// UserLifecycleManagement checks CC6.2: User lifecycle policies must exist.
type UserLifecycleManagement struct {
	engine.BaseCheck
}

func (c *UserLifecycleManagement) init() {
	c.CheckID = "CC6.2"
	c.CheckTitle = "User lifecycle management policies must be configured"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"PS-4", "PS-5"},
	}
}

func (c *UserLifecycleManagement) ID() string                           { c.init(); return c.CheckID }
func (c *UserLifecycleManagement) Title() string                        { c.init(); return c.CheckTitle }
func (c *UserLifecycleManagement) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *UserLifecycleManagement) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *UserLifecycleManagement) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *UserLifecycleManagement) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.LifecyclePolicies()
	if err != nil {
		return nil, err
	}

	if len(policies) > 0 {
		var names []string
		for _, p := range policies {
			names = append(names, p.Name)
		}
		return []engine.Finding{{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        fmt.Sprintf("Found %d lifecycle policy(ies): %s", len(policies), strings.Join(names, ", ")),
			Evidence:        map[string]any{"policyCount": len(policies), "policies": names},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
		Status:          engine.StatusFail,
		Comments:        "No user lifecycle policies found",
		Remediation:     "Configure lifecycle policies to manage user provisioning, deprovisioning, and access reviews",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// ---------------------------------------------------------------------------
// CC6.3: Role-based access control
// ---------------------------------------------------------------------------

// RoleBasedAccessControl checks CC6.3: Groups must reflect role-based access patterns.
type RoleBasedAccessControl struct {
	engine.BaseCheck
}

func (c *RoleBasedAccessControl) init() {
	c.CheckID = "CC6.3"
	c.CheckTitle = "Role-based access control must be implemented via groups"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"pcidss": {"7.2.1"},
	}
}

func (c *RoleBasedAccessControl) ID() string                           { c.init(); return c.CheckID }
func (c *RoleBasedAccessControl) Title() string                        { c.init(); return c.CheckTitle }
func (c *RoleBasedAccessControl) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *RoleBasedAccessControl) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *RoleBasedAccessControl) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *RoleBasedAccessControl) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	groups, err := ec.Groups()
	if err != nil {
		return nil, err
	}

	roleKeywords := []string{"admin", "user", "developer", "analyst", "manager"}
	var roleGroups []string
	for _, group := range groups {
		name := strings.ToLower(group.Profile.Name)
		for _, kw := range roleKeywords {
			if strings.Contains(name, kw) {
				roleGroups = append(roleGroups, group.Profile.Name)
				break
			}
		}
	}

	var findings []engine.Finding
	if len(roleGroups) > 0 {
		findings = append(findings, engine.Finding{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        fmt.Sprintf("Found %d role-based group(s): %s", len(roleGroups), strings.Join(roleGroups, ", ")),
			Evidence:        map[string]any{"roleGroups": roleGroups, "totalGroups": len(groups)},
			CrossReferences: c.CrossRefs,
		})
	} else {
		findings = append(findings, engine.Finding{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusFail,
			Comments:        fmt.Sprintf("No role-based groups found among %d groups (expected names containing admin/user/developer/analyst/manager)", len(groups)),
			Remediation:     "Create groups that reflect organizational roles (e.g., Admins, Developers, Analysts) for role-based access control",
			CrossReferences: c.CrossRefs,
		})
	}

	return findings, nil
}

// ---------------------------------------------------------------------------
// CC6.6: Session security
// ---------------------------------------------------------------------------

// SessionSecurity checks CC6.6: Session idle timeout must not exceed 30 minutes.
type SessionSecurity struct {
	engine.BaseCheck
}

func (c *SessionSecurity) init() {
	c.CheckID = "CC6.6"
	c.CheckTitle = "Session idle timeout must not exceed 30 minutes"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":   {"V-273186"},
		"pcidss": {"8.2.8"},
	}
}

func (c *SessionSecurity) ID() string                           { c.init(); return c.CheckID }
func (c *SessionSecurity) Title() string                        { c.init(); return c.CheckTitle }
func (c *SessionSecurity) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SessionSecurity) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SessionSecurity) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SessionSecurity) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
			if idle > 30 {
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:          engine.StatusFail,
					Comments:        fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout (max 30 for SOC 2)", policy.Name, rule.Name, idle),
					Evidence:        map[string]any{"policy": policy.Name, "rule": rule.Name, "idleTimeout": idle},
					CrossReferences: c.CrossRefs,
				})
			} else if idle > 0 {
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:          engine.StatusPass,
					Comments:        fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout", policy.Name, rule.Name, idle),
					Evidence:        map[string]any{"policy": policy.Name, "rule": rule.Name, "idleTimeout": idle},
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

// ---------------------------------------------------------------------------
// CC6.7: Trusted origins for secure transmission
// ---------------------------------------------------------------------------

// TrustedOriginsCheck checks CC6.7: Trusted origins must be configured for secure transmission.
type TrustedOriginsCheck struct {
	engine.BaseCheck
}

func (c *TrustedOriginsCheck) init() {
	c.CheckID = "CC6.7"
	c.CheckTitle = "Trusted origins must be configured for secure data transmission"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"SC-8"},
	}
}

func (c *TrustedOriginsCheck) ID() string                           { c.init(); return c.CheckID }
func (c *TrustedOriginsCheck) Title() string                        { c.init(); return c.CheckTitle }
func (c *TrustedOriginsCheck) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *TrustedOriginsCheck) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *TrustedOriginsCheck) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *TrustedOriginsCheck) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	origins, err := ec.TrustedOrigins()
	if err != nil {
		return nil, err
	}

	if len(origins) > 0 {
		var names []string
		for _, o := range origins {
			names = append(names, o.Name)
		}
		return []engine.Finding{{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        fmt.Sprintf("Found %d trusted origin(s): %s", len(origins), strings.Join(names, ", ")),
			Evidence:        map[string]any{"originCount": len(origins), "origins": names},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
		Status:          engine.StatusFail,
		Comments:        "No trusted origins configured",
		Remediation:     "Configure trusted origins to control CORS and redirect URIs for secure data transmission",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// ---------------------------------------------------------------------------
// CC6.8: Unauthorized access prevention
// ---------------------------------------------------------------------------

// UnauthorizedAccessPrevention checks CC6.8: Network zones and behaviors must exist.
type UnauthorizedAccessPrevention struct {
	engine.BaseCheck
}

func (c *UnauthorizedAccessPrevention) init() {
	c.CheckID = "CC6.8"
	c.CheckTitle = "Network zones and behavior detection must be configured to prevent unauthorized access"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"SC-7"},
	}
}

func (c *UnauthorizedAccessPrevention) ID() string        { c.init(); return c.CheckID }
func (c *UnauthorizedAccessPrevention) Title() string     { c.init(); return c.CheckTitle }
func (c *UnauthorizedAccessPrevention) Severity() engine.Severity { c.init(); return c.CheckSeverity }
func (c *UnauthorizedAccessPrevention) Automated() bool   { c.init(); return c.IsAutomated }
func (c *UnauthorizedAccessPrevention) CrossReferences() map[string][]string {
	c.init()
	return c.CrossRefs
}

func (c *UnauthorizedAccessPrevention) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()

	zones, _ := ec.NetworkZones()
	behaviors, _ := ec.Behaviors()

	hasZones := len(zones) > 0
	hasBehaviors := len(behaviors) > 0

	var findings []engine.Finding

	if hasZones && hasBehaviors {
		findings = append(findings, engine.Finding{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        fmt.Sprintf("Unauthorized access prevention configured: %d network zone(s), %d behavior rule(s)", len(zones), len(behaviors)),
			Evidence:        map[string]any{"networkZones": len(zones), "behaviors": len(behaviors)},
			CrossReferences: c.CrossRefs,
		})
	} else {
		var missing []string
		if !hasZones {
			missing = append(missing, "network zones")
		}
		if !hasBehaviors {
			missing = append(missing, "behavior detection rules")
		}
		findings = append(findings, engine.Finding{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusFail,
			Comments:        fmt.Sprintf("Missing unauthorized access prevention controls: %s", strings.Join(missing, ", ")),
			Remediation:     "Configure network zones to restrict access by IP/location and enable behavior detection rules",
			Evidence:        map[string]any{"networkZones": len(zones), "behaviors": len(behaviors)},
			CrossReferences: c.CrossRefs,
		})
	}

	return findings, nil
}
