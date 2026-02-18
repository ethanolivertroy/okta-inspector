package okta

import (
	"net/url"
	"regexp"
	"strings"
)

var linkRegex = regexp.MustCompile(`<([^>]+)>;\s*rel="([^"]+)"`)

// parseLinkHeader extracts the URL for the given rel from an HTTP Link header.
func parseLinkHeader(header, rel string) string {
	if header == "" {
		return ""
	}

	for _, part := range strings.Split(header, ",") {
		matches := linkRegex.FindStringSubmatch(strings.TrimSpace(part))
		if len(matches) == 3 && matches[2] == rel {
			return matches[1]
		}
	}
	return ""
}

// validatePaginationURL ensures the next-page URL shares the same origin as baseURL
// to prevent SSRF via a malicious Link header.
func validatePaginationURL(nextURL, baseURL string) bool {
	next, err := url.Parse(nextURL)
	if err != nil {
		return false
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	return next.Scheme == base.Scheme && next.Host == base.Host
}
