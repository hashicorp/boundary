package plugin

import (
	"github.com/hashicorp/boundary/internal/plugin/store"
)

// A PluginVersion contains plugin executables. It is owned by
// a plugin.
type PluginVersion struct {
	*store.PluginVersion
	tableName string `gorm:"-"`
}

// NewPluginVersion creates a new in memory PluginVersion assigned to a Plugin.
// All options are ignored.
func NewPluginVersion(pluginId, ver string, _ ...Option) *PluginVersion {
	p := &PluginVersion{
		PluginVersion: &store.PluginVersion{
			SemanticVersion: ver,
			PluginId:        pluginId,
		},
	}
	return p
}

// TableName returns the table name for the host plugin.
func (c *PluginVersion) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "plugin_version"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *PluginVersion) SetTableName(n string) {
	c.tableName = n
}
