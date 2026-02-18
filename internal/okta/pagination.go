package okta

import (
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
