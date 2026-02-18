package app

import "github.com/ethanolivertroy/okta-inspector/internal/okta"

// Options configures the application.
type Options struct {
	Domain       string
	AuthHeader   string
	OutputDir    string
	Frameworks   []string // empty = all
	Format       string   // "markdown", "json", "both"
	SaveSnapshot bool
	FromSnapshot string // path to load snapshot instead of API calls
	Quiet        bool
	PageSize     int
	MaxPages     int
	OnProgress   okta.ProgressFunc
}
