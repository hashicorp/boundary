// +build dev

package base

func init() {
	DevOnlyControllerFlags = addDevOnlyControllerFlags
}

func addDevOnlyControllerFlags(c *Command, f *FlagSet) {
	f.StringVar(&StringVar{
		Name:   "dev-passthrough-directory",
		Target: &c.FlagDevPassthroughDirectory,
		EnvVar: "BOUNDARY_DEV_PASSTHROUGH_DIRECTORY",
		Usage:  "Enables a passthrough directory in the webserver at /",
	})

	f.StringVar(&StringVar{
		Name:   "dev-recovery-key",
		Target: &c.FlagDevRecoveryKey,
		EnvVar: "BOUNDARY_DEV_RECOVERY_KEY",
		Usage:  "Specifies the base64'd 256-bit AES key to use for recovery operations",
	})
}
