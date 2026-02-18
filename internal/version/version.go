package version

import (
	"fmt"
	"runtime"
)

// Set via ldflags at build time.
var (
	Version   = "dev"
	Commit    = "none"
	Date      = "unknown"
	GoVersion = runtime.Version()
)

func Full() string {
	return fmt.Sprintf("okta-inspector %s (%s) built %s with %s", Version, Commit, Date, GoVersion)
}

func Short() string {
	return Version
}
