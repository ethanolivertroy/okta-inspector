package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProgressFunc is called during snapshot collection to report progress.
type ProgressFunc func(phase string, current, total int, message string)

// Client provides access to the Okta Management API.
type Client struct {
	BaseURL    string
	AuthHeader string
	HTTPClient *http.Client
	PageSize   int
	MaxPages   int
	OnProgress ProgressFunc

	apiCallCount int
}

// NewClient creates a new Okta API client.
func NewClient(domain, authHeader string) *Client {
	baseURL := fmt.Sprintf("https://%s/api/v1", strings.TrimSuffix(domain, "/"))
	return &Client{
		BaseURL:    baseURL,
		AuthHeader: authHeader,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		PageSize:   200,
		MaxPages:   10,
	}
}

// APICallCount returns the total number of API calls made.
func (c *Client) APICallCount() int {
	return c.apiCallCount
}

// progress reports progress if a callback is set.
func (c *Client) progress(phase string, current, total int, msg string) {
	if c.OnProgress != nil {
		c.OnProgress(phase, current, total, msg)
	}
}

// get performs a single GET request with auth headers.
func (c *Client) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.AuthHeader)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	c.apiCallCount++
	return c.HTTPClient.Do(req)
}

// fetchJSON fetches a single JSON endpoint (no pagination).
func (c *Client) fetchJSON(ctx context.Context, endpoint string) (json.RawMessage, error) {
	url := c.BaseURL + endpoint
	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if err := handleRateLimit(ctx, resp, c); err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET %s: status %d: %s", endpoint, resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response for %s: %w", endpoint, err)
	}
	return json.RawMessage(data), nil
}

// fetchList fetches a paginated list endpoint.
func (c *Client) fetchList(ctx context.Context, endpoint string) (json.RawMessage, error) {
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	url := fmt.Sprintf("%s%s%slimit=%d", c.BaseURL, endpoint, sep, c.PageSize)
	var allResults []json.RawMessage

	for page := 0; page < c.MaxPages && url != ""; page++ {
		resp, err := c.get(ctx, url)
		if err != nil {
			if len(allResults) > 0 {
				break
			}
			return nil, fmt.Errorf("GET %s: %w", endpoint, err)
		}

		if err := handleRateLimit(ctx, resp, c); err != nil {
			resp.Body.Close()
			if len(allResults) > 0 {
				break
			}
			return nil, err
		}

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(allResults) > 0 {
				break
			}
			return nil, fmt.Errorf("GET %s: status %d: %s", endpoint, resp.StatusCode, string(body))
		}

		var items []json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
			resp.Body.Close()
			if len(allResults) > 0 {
				break
			}
			return nil, fmt.Errorf("decoding %s: %w", endpoint, err)
		}
		resp.Body.Close()

		allResults = append(allResults, items...)
		nextURL := parseLinkHeader(resp.Header.Get("Link"), "next")
		if nextURL != "" && !validatePaginationURL(nextURL, c.BaseURL) {
			break // refuse to follow redirects to a different origin
		}
		url = nextURL
	}

	if len(allResults) == 0 {
		return json.RawMessage("[]"), nil
	}

	data, err := json.Marshal(allResults)
	if err != nil {
		return nil, fmt.Errorf("marshaling results for %s: %w", endpoint, err)
	}
	return data, nil
}

// TestConnection verifies API connectivity.
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.fetchList(ctx, "/users?limit=1")
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	return nil
}

// CollectSnapshot gathers all tenant data into a Snapshot.
func (c *Client) CollectSnapshot(ctx context.Context, domain string) (*Snapshot, error) {
	snap := &Snapshot{
		Domain:      domain,
		Collected:   time.Now().UTC(),
		PolicyRules: make(map[string]json.RawMessage),
	}

	type fetchTask struct {
		name     string
		endpoint string
		isList   bool
		dest     *json.RawMessage
		maxPages int // override MaxPages if set
	}

	tasks := []fetchTask{
		// Policies
		{name: "sign-on policies", endpoint: "/policies?type=OKTA_SIGN_ON", dest: &snap.SignOnPolicies},
		{name: "password policies", endpoint: "/policies?type=PASSWORD", dest: &snap.PasswordPolicies},
		{name: "MFA enrollment policies", endpoint: "/policies?type=MFA_ENROLL", dest: &snap.MFAEnrollmentPolicies},
		{name: "access policies", endpoint: "/policies?type=ACCESS_POLICY", dest: &snap.AccessPolicies},
		{name: "lifecycle policies", endpoint: "/policies?type=USER_LIFECYCLE", dest: &snap.LifecyclePolicies},

		// Users & Groups
		{name: "users", endpoint: "/users", isList: true, dest: &snap.Users},
		{name: "groups", endpoint: "/groups", isList: true, dest: &snap.Groups},

		// Apps
		{name: "applications", endpoint: "/apps", isList: true, dest: &snap.Apps},

		// Authenticators
		{name: "authenticators", endpoint: "/authenticators", dest: &snap.Authenticators},

		// Auth Servers
		{name: "authorization servers", endpoint: "/authorizationServers", dest: &snap.AuthorizationServers},

		// Identity Providers
		{name: "identity providers", endpoint: "/idps", dest: &snap.IdentityProviders},

		// Security
		{name: "network zones", endpoint: "/zones", dest: &snap.NetworkZones},
		{name: "trusted origins", endpoint: "/trustedOrigins", dest: &snap.TrustedOrigins},
		{name: "threat insight", endpoint: "/threats/configuration", dest: &snap.ThreatInsight},
		{name: "behaviors", endpoint: "/behaviors", dest: &snap.Behaviors},

		// Monitoring
		{name: "event hooks", endpoint: "/eventHooks", dest: &snap.EventHooks},
		{name: "log streams", endpoint: "/logStreams", dest: &snap.LogStreams},

		// Additional
		{name: "domains", endpoint: "/domains", dest: &snap.Domains},
		{name: "brands", endpoint: "/brands", dest: &snap.Brands},
		{name: "org factors", endpoint: "/org/factors", dest: &snap.OrgFactors},
	}

	total := len(tasks)
	for i, task := range tasks {
		c.progress("collection", i+1, total, "Fetching "+task.name)

		var data json.RawMessage
		var err error
		if task.isList {
			data, err = c.fetchList(ctx, task.endpoint)
		} else {
			data, err = c.fetchJSON(ctx, task.endpoint)
		}
		if err != nil {
			// Non-fatal: log and continue with nil data
			c.progress("collection", i+1, total, fmt.Sprintf("Warning: %s: %v", task.name, err))
			continue
		}
		*task.dest = data
	}

	// Fetch password policy rules
	c.progress("collection", total, total, "Fetching policy rules")
	if err := c.collectPolicyRules(ctx, snap); err != nil {
		c.progress("collection", total, total, fmt.Sprintf("Warning: policy rules: %v", err))
	}

	// Fetch system logs (limited pages)
	c.progress("collection", total, total, "Fetching system logs")
	origMaxPages := c.MaxPages
	c.MaxPages = 3
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	logs, err := c.fetchList(ctx, fmt.Sprintf("/logs?since=%s", since))
	if err == nil {
		snap.SystemLogs = logs
	}
	c.MaxPages = origMaxPages

	return snap, nil
}

// collectPolicyRules fetches rules for each password policy and sign-on policy.
func (c *Client) collectPolicyRules(ctx context.Context, snap *Snapshot) error {
	// Collect rules for sign-on and password policies
	for _, raw := range []json.RawMessage{snap.SignOnPolicies, snap.PasswordPolicies} {
		if raw == nil {
			continue
		}
		var policies []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &policies); err != nil {
			continue
		}
		for _, p := range policies {
			rules, err := c.fetchJSON(ctx, fmt.Sprintf("/policies/%s/rules", p.ID))
			if err != nil {
				continue
			}
			snap.PolicyRules[p.ID] = rules
		}
	}
	return nil
}
