package okta

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// handleRateLimit checks for 429 responses and rate limit headers.
// If rate limited, it waits and returns an error to trigger retry.
func handleRateLimit(ctx context.Context, resp *http.Response, c *Client) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		wait := rateLimitWait(resp)
		c.progress("collection", 0, 0, fmt.Sprintf("Rate limited, waiting %v", wait))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		return fmt.Errorf("rate limited, retry after %v", wait)
	}

	// Proactively wait if remaining is very low
	remaining := resp.Header.Get("X-Rate-Limit-Remaining")
	if remaining != "" {
		rem, err := strconv.Atoi(remaining)
		if err == nil && rem < 10 {
			wait := rateLimitWait(resp)
			if wait > 0 {
				c.progress("collection", 0, 0, fmt.Sprintf("Rate limit low (%d remaining), pausing %v", rem, wait))
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(wait):
				}
			}
		}
	}

	return nil
}

// rateLimitWait calculates how long to wait based on X-Rate-Limit-Reset header.
func rateLimitWait(resp *http.Response) time.Duration {
	resetHeader := resp.Header.Get("X-Rate-Limit-Reset")
	if resetHeader != "" {
		resetEpoch, err := strconv.ParseInt(resetHeader, 10, 64)
		if err == nil {
			resetTime := time.Unix(resetEpoch, 0)
			wait := time.Until(resetTime) + time.Second
			if wait > 0 && wait < 2*time.Minute {
				return wait
			}
		}
	}
	return 5 * time.Second
}
