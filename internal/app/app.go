package app

import (
	"fmt"

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
// Panics on duplicate registration, which indicates a programming error.
func registerFrameworks(reg *engine.Registry) {
	frameworks := []engine.Framework{
		stig.New(), fedramp.New(), irap.New(),
		ismap.New(), soc2.New(), pcidss.New(),
	}
	for _, fw := range frameworks {
		if err := reg.Register(fw); err != nil {
			panic(fmt.Sprintf("registering framework %s: %v", fw.ID(), err))
		}
	}
}
