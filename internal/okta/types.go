package okta

import "time"

// Policy represents an Okta policy (sign-on, password, MFA enrollment, access, lifecycle).
type Policy struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Status     string          `json:"status"`
	Priority   int             `json:"priority"`
	System     bool            `json:"system"`
	Conditions *PolicyConditions `json:"conditions,omitempty"`
	Settings   *PolicySettings   `json:"settings,omitempty"`
}

type PolicyConditions struct {
	People      *PeopleCondition  `json:"people,omitempty"`
	Network     *NetworkCondition `json:"network,omitempty"`
	AuthContext *AuthContext       `json:"authContext,omitempty"`
	Risk        *RiskCondition    `json:"risk,omitempty"`
	RiskScore   *RiskScore        `json:"riskScore,omitempty"`
	Device      *DeviceCondition  `json:"device,omitempty"`
}

type PeopleCondition struct {
	Groups *GroupCondition `json:"groups,omitempty"`
	Users  *UserCondition `json:"users,omitempty"`
}

type GroupCondition struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

type UserCondition struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

type NetworkCondition struct {
	Connection string   `json:"connection,omitempty"`
	Include    []string `json:"include,omitempty"`
	Exclude    []string `json:"exclude,omitempty"`
}

type AuthContext struct {
	AuthType string `json:"authType,omitempty"`
}

type RiskCondition struct {
	Behaviors []string `json:"behaviors,omitempty"`
}

type RiskScore struct {
	Level string `json:"level,omitempty"`
}

type DeviceCondition struct {
	Registered  bool   `json:"registered,omitempty"`
	Managed     bool   `json:"managed,omitempty"`
	TrustLevel  string `json:"trustLevel,omitempty"`
}

type PolicySettings struct {
	Password   *PasswordSettings   `json:"password,omitempty"`
	Delegation *DelegationSettings `json:"delegation,omitempty"`
	Factors    *FactorsSettings    `json:"factors,omitempty"`
}

type PasswordSettings struct {
	Complexity *PasswordComplexity `json:"complexity,omitempty"`
	Age        *PasswordAge        `json:"age,omitempty"`
	Lockout    *PasswordLockout    `json:"lockout,omitempty"`
}

type PasswordComplexity struct {
	MinLength         int      `json:"minLength"`
	MinLowerCase      int      `json:"minLowerCase"`
	MinUpperCase      int      `json:"minUpperCase"`
	MinNumber         int      `json:"minNumber"`
	MinSymbol         int      `json:"minSymbol"`
	ExcludeUsername   bool     `json:"excludeUsername"`
	ExcludeAttributes []string `json:"excludeAttributes,omitempty"`
	Dictionary        *Dictionary `json:"dictionary,omitempty"`
}

type Dictionary struct {
	Common *DictionaryCommon `json:"common,omitempty"`
}

type DictionaryCommon struct {
	Exclude bool `json:"exclude"`
}

type PasswordAge struct {
	MaxAgeDays     int `json:"maxAgeDays"`
	ExpireWarnDays int `json:"expireWarnDays"`
	MinAgeMinutes  int `json:"minAgeMinutes"`
	HistoryCount   int `json:"historyCount"`
}

type PasswordLockout struct {
	MaxAttempts         int  `json:"maxAttempts"`
	AutoUnlockMinutes   int  `json:"autoUnlockMinutes"`
	ShowLockoutFailures bool `json:"showLockoutFailures"`
}

type DelegationSettings struct {
	Options *DelegationOptions `json:"options,omitempty"`
}

type DelegationOptions struct {
	SkipUnlock bool `json:"skipUnlock"`
}

type FactorsSettings struct {
	// Embedded factor settings
}

// PolicyRule represents a rule within an Okta policy.
type PolicyRule struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Type       string              `json:"type"`
	Status     string              `json:"status"`
	Priority   int                 `json:"priority"`
	System     bool                `json:"system"`
	Conditions *PolicyRuleConditions `json:"conditions,omitempty"`
	Actions    *PolicyRuleActions    `json:"actions,omitempty"`
}

type PolicyRuleConditions struct {
	People      *PeopleCondition  `json:"people,omitempty"`
	Network     *NetworkCondition `json:"network,omitempty"`
	AuthContext *AuthContext       `json:"authContext,omitempty"`
	Risk        *RiskCondition    `json:"risk,omitempty"`
}

type PolicyRuleActions struct {
	SignOn   *SignOnAction   `json:"signon,omitempty"`
	Password *PasswordAction `json:"passwordChange,omitempty"`
}

type SignOnAction struct {
	Access                string          `json:"access,omitempty"`
	FactorMode            string          `json:"factorMode,omitempty"`
	FactorPromptMode      string          `json:"factorPromptMode,omitempty"`
	RememberDeviceByDefault bool          `json:"rememberDeviceByDefault,omitempty"`
	Session               *SessionAction  `json:"session,omitempty"`
}

type SessionAction struct {
	MaxSessionIdleMinutes    int  `json:"maxSessionIdleMinutes"`
	MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
	UsePersistentCookie      bool `json:"usePersistentCookie"`
}

type PasswordAction struct {
	Access string `json:"access,omitempty"`
}

// User represents an Okta user.
type User struct {
	ID              string    `json:"id"`
	Status          string    `json:"status"`
	Created         time.Time `json:"created"`
	Activated       *time.Time `json:"activated,omitempty"`
	LastLogin       *time.Time `json:"lastLogin,omitempty"`
	LastUpdated     time.Time `json:"lastUpdated"`
	StatusChanged   *time.Time `json:"statusChanged,omitempty"`
	PasswordChanged *time.Time `json:"passwordChanged,omitempty"`
	Profile         UserProfile `json:"profile"`
}

type UserProfile struct {
	Login     string `json:"login"`
	Email     string `json:"email"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

// Group represents an Okta group.
type Group struct {
	ID      string       `json:"id"`
	Type    string       `json:"type"`
	Profile GroupProfile `json:"profile"`
}

type GroupProfile struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// App represents an Okta application.
type App struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Label       string `json:"label"`
	Status      string `json:"status"`
	SignOnMode   string `json:"signOnMode,omitempty"`
	Features    []string `json:"features,omitempty"`
}

// Authenticator represents an Okta authenticator (MFA factor).
type Authenticator struct {
	ID       string                 `json:"id"`
	Key      string                 `json:"key"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Status   string                 `json:"status"`
	Provider *AuthenticatorProvider `json:"provider,omitempty"`
	Settings map[string]any         `json:"settings,omitempty"`
}

type AuthenticatorProvider struct {
	Type          string `json:"type,omitempty"`
	Configuration map[string]any `json:"configuration,omitempty"`
}

// IdentityProvider represents an Okta IdP.
type IdentityProvider struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Protocol map[string]any `json:"protocol,omitempty"`
}

// NetworkZone represents an Okta network zone.
type NetworkZone struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Status   string `json:"status"`
	Usage    string `json:"usage,omitempty"`
}

// TrustedOrigin represents a trusted origin.
type TrustedOrigin struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Origin string   `json:"origin"`
	Scopes []Scope  `json:"scopes,omitempty"`
	Status string   `json:"status"`
}

type Scope struct {
	Type string `json:"type"`
}

// EventHook represents an Okta event hook.
type EventHook struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Channel map[string]any `json:"channel,omitempty"`
	Events  map[string]any `json:"events,omitempty"`
}

// LogStream represents an Okta log stream.
type LogStream struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Status  string `json:"status"`
}

// Behavior represents an Okta behavior detection rule.
type Behavior struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// ThreatInsight represents Okta ThreatInsight configuration.
type ThreatInsight struct {
	Action         string   `json:"action"`
	ExcludeZones   []string `json:"excludeZones,omitempty"`
}

// AuthorizationServer represents an Okta authorization server.
type AuthorizationServer struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Audiences   []string `json:"audiences,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Status      string `json:"status"`
}

// SystemLog represents a single Okta system log event.
type SystemLog struct {
	Actor       *LogActor     `json:"actor,omitempty"`
	EventType   string        `json:"eventType"`
	DisplayMessage string     `json:"displayMessage,omitempty"`
	Outcome     *LogOutcome   `json:"outcome,omitempty"`
	Published   time.Time     `json:"published"`
	Severity    string        `json:"severity"`
}

type LogActor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"displayName,omitempty"`
}

type LogOutcome struct {
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
}
