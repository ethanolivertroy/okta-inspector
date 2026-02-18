package app

import (
	"github.com/ethanolivertroy/okta-inspector/internal/engine"
	"github.com/ethanolivertroy/okta-inspector/internal/framework/fedramp"
	"github.com/ethanolivertroy/okta-inspector/internal/framework/irap"
	"github.com/ethanolivertroy/okta-inspector/internal/framework/ismap"
	"github.com/ethanolivertroy/okta-inspector/internal/framework/pcidss"
	"github.com/ethanolivertroy/okta-inspector/internal/framework/soc2"
	"github.com/ethanolivertroy/okta-inspector/internal/framework/stig"
	"github.com/ethanolivertroy/okta-inspector/internal/okta"
)

// App wires together the Okta client, engine, and configuration.
type App struct {
	Client   *okta.Client
	Engine   *engine.Engine
	Registry *engine.Registry
	Options  Options
}

// New creates an App with all frameworks registered.
func New(opts Options) *App {
	client := okta.NewClient(opts.Domain, opts.AuthHeader)
	client.OnProgress = opts.OnProgress
	if opts.PageSize > 0 {
		client.PageSize = opts.PageSize
	}
	if opts.MaxPages > 0 {
		client.MaxPages = opts.MaxPages
	}

	reg := engine.NewRegistry()
	registerFrameworks(reg)

	// Filter to requested frameworks if specified
	if len(opts.Frameworks) > 0 {
		reg = reg.Filter(opts.Frameworks)
	}

	eng := engine.NewEngine(reg)

	return &App{
		Client:   client,
		Engine:   eng,
		Registry: reg,
		Options:  opts,
	}
}

// registerFrameworks adds all built-in compliance frameworks.
func registerFrameworks(reg *engine.Registry) {
	_ = reg.Register(stig.New())
	_ = reg.Register(fedramp.New())
	_ = reg.Register(irap.New())
	_ = reg.Register(ismap.New())
	_ = reg.Register(soc2.New())
	_ = reg.Register(pcidss.New())
}
