package main

import (
	"os"

	"github.com/ethanolivertroy/okta-inspector/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
