// +build dev

package controller

import "github.com/hashicorp/watchtower/internal/cmd/base"

func init() {
	devOnlyControllerFlags = addDevOnlyControllerFlags
}

func addDevOnlyControllerFlags(c *Command, f *base.FlagSet) {
	f.StringVar(&base.StringVar{
		Name:   "dev-passthrough-directory",
		Target: &c.flagDevPassthroughDirectory,
		EnvVar: "WATCHTOWER_DEV_PASSTHROUGH_DIRECTORY",
		Usage:  "Enables a passthrough directory in the webserver at /",
	})
}
