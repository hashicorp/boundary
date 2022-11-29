package version

var (
	// The git commit that was compiled. This will be filled in by the compiler.
	GitCommit   string
	GitDescribe string

	// Whether cgo is enabled or not; set at build time
	CgoEnabled bool

	// Default values - set when building locally (at build time)
	Version           = "0.0.0"
	VersionPrerelease = "dev"
	VersionMetadata   = ""
)
