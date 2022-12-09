package version

var (
	// GitCommit is the git commit that was compiled. This will be filled in by the compiler.
	GitCommit   string
	GitDescribe string

	// CgoEnabled is whether cgo is enabled or not; set at build time
	CgoEnabled bool

	// Version is the base version
	// Default values - set when building locally (at build time)
	Version = "0.0.0"
	// VersionPrerelease is the prerelease version information
	VersionPrerelease = "dev"
	VersionMetadata   = ""
)
