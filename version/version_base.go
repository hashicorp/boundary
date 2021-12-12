package version

var (
	// The git commit that was compiled. This will be filled in by the compiler.
	GitCommit   string
	GitDescribe string

	// Whether cgo is enabled or not; set at build time
	CgoEnabled bool

	// Version is set at compile time when using 'make build' or building in CI.
	Version = "0.7.2"

	// VersionPrerelease is also set at compile time, similarly to Version.
	VersionPrerelease = ""

	VersionMetadata = ""
)
