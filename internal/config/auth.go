package config

import (
	"fmt"
	"os"
	"strings"
)

// TokenType distinguishes SSWS API tokens from OAuth bearer tokens.
type TokenType int

const (
	TokenSSWS TokenType = iota
	TokenBearer
)

// ResolvedAuth holds a resolved token and its type.
type ResolvedAuth struct {
	Token     string
	TokenType TokenType
}

// AuthHeader returns the Authorization header value.
func (a *ResolvedAuth) AuthHeader() string {
	switch a.TokenType {
	case TokenBearer:
		return "Bearer " + a.Token
	default:
		return "SSWS " + a.Token
	}
}

// ResolveAuth determines the API token from (in priority order):
// 1. Explicit flag value
// 2. Environment variable OKTA_API_TOKEN
// 3. Keychain (future)
func ResolveAuth(flagToken string, oauth bool) (*ResolvedAuth, error) {
	token := flagToken

	// Try environment variable if no flag
	if token == "" {
		token = os.Getenv(EnvOktaAPIToken)
	}

	if token == "" {
		return nil, fmt.Errorf("no API token provided; use --token flag or set %s", EnvOktaAPIToken)
	}

	auth := &ResolvedAuth{Token: token}

	// Determine token type
	if oauth || strings.HasPrefix(token, "Bearer ") {
		auth.Token = strings.TrimPrefix(token, "Bearer ")
		auth.TokenType = TokenBearer
	} else {
		auth.Token = strings.TrimPrefix(token, "SSWS ")
		auth.TokenType = TokenSSWS
	}

	return auth, nil
}

// ResolveDomain determines the Okta domain from (in priority order):
// 1. Explicit flag value
// 2. Environment variable OKTA_DOMAIN
// 3. OKTA_ORG_URL environment variable (extracts domain)
func ResolveDomain(flagDomain string) (string, error) {
	domain := flagDomain

	if domain == "" {
		domain = os.Getenv(EnvOktaDomain)
	}

	if domain == "" {
		orgURL := os.Getenv(EnvOktaOrgURL)
		if orgURL != "" {
			// Extract domain from URL like https://dev-12345.okta.com
			domain = strings.TrimPrefix(orgURL, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.TrimSuffix(domain, "/")
		}
	}

	if domain == "" {
		return "", fmt.Errorf("no Okta domain provided; use --domain flag or set %s", EnvOktaDomain)
	}

	domain = strings.TrimSuffix(domain, "/")
	return domain, nil
}
