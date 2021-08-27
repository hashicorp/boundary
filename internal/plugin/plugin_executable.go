package plugin

import (
	"github.com/hashicorp/boundary/internal/plugin/store"
)

// A PluginExecutable is owned by a plugin version.
type PluginExecutable struct {
	*store.PluginExecutable
	tableName string `gorm:"-"`
}

// PluginVersion creates a new in memory PluginExecutable assigned to a PluginVersion.
// All options are ignored.
func NewPluginExecutable(versionId, os, arch string, exe []byte, _ ...Option) *PluginExecutable {
	p := &PluginExecutable{
		PluginExecutable: &store.PluginExecutable{
			VersionId:       versionId,
			OperatingSystem: os,
			Architecture:    arch,
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
