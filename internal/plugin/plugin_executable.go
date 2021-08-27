package plugin

import (
	"github.com/hashicorp/boundary/internal/plugin/store"
)

// OperatingSystem defines the operating systems supported for plugin executables
type OperatingSystem string

const (
	UnknownOS   OperatingSystem = "unknown"
	AixOS                       = "aix"
	AndroidOS                   = "android"
	DarwinOS                    = "darwin"
	DragonflyOS                 = "dragonfly"
	FreebsdOS                   = "freebsd"
	illumosOS                   = "illumos"
	iosOS                       = "ios"
	jsOS                        = "js"
	LinuxOS                     = "linux"
	netbsdOS                    = "netbsd"
	openbsdOS                   = "openbsd"
	plan9OS                     = "plan9"
	solarisOS                   = "solaris"
	WindowsOS                   = "windows"
)

type Architecture string

const (
	UnknownArch  Architecture = "unknown"
	Three86Arch               = "386"
	Amd64Arch                 = "amd64"
	armArch                   = "arm"
	arm64Arch                 = "arm64"
	mipsArch                  = "mips"
	mips64Arch                = "mips64"
	mips64leArch              = "mips64le"
	mipsleArch                = "mipsle"
	ppc64Arch                 = "ppc64"
	ppc64leArch               = "ppc64le"
	riscv64Arch               = "riscv64"
	s390xArch                 = "s390x"
	wasmArch                  = "wasm"
)

// A PluginExecutable is owned by a plugin version.
type PluginExecutable struct {
	*store.PluginExecutable
	tableName string `gorm:"-"`
}

// PluginVersion creates a new in memory PluginExecutable assigned to a PluginVersion.
// All options are ignored.
func NewPluginExecutable(versionId string, os OperatingSystem, arch Architecture, exe []byte, _ ...Option) *PluginExecutable {
	p := &PluginExecutable{
		PluginExecutable: &store.PluginExecutable{
			VersionId:       versionId,
			OperatingSystem: string(os),
			Architecture:    string(arch),
			Executable:      exe,
		},
	}
	return p
}

// TableName returns the table name for the host plugin.
func (c *PluginExecutable) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "plugin_executable"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *PluginExecutable) SetTableName(n string) {
	c.tableName = n
}
