package version

var (
	// The git commit that was compiled. This will be filled in by the compiler.
	GitCommit   string
	GitDescribe string

	// Whether cgo is enabled or not; set at build time
	CgoEnabled bool

	Version = "0.10.2"

	// VersionPrerelease is also set at compile time, similarly to Version.
	VersionPrerelease = ""

	VersionMetadata = ""
)
