// +build dev

package dev

import "github.com/hashicorp/boundary/internal/cmd/base"

func init() {
	devOnlyControllerFlags = addDevOnlyControllerFlags
}

func addDevOnlyControllerFlags(c *Command, f *base.FlagSet) {
	f.StringVar(&base.StringVar{
		Name:   "dev-passthrough-directory",
		Target: &c.flagDevPassthroughDirectory,
		EnvVar: "BOUNDARY_DEV_PASSTHROUGH_DIRECTORY",
		Usage:  "Enables a passthrough directory in the webserver at /",
	})
}
