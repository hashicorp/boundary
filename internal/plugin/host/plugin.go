package host

import (
	"github.com/hashicorp/boundary/internal/plugin/host/store"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// A Plugin enables additional logic to be used by boundary.
// It is owned by a scope.
type Plugin struct {
	*store.Plugin
	tableName string `gorm:"-"`
}

// NewPlugin creates a new in memory Plugin assigned to the global scope.
// Name, Description are the only allowed option. All other options are ignored.
func NewPlugin(pluginName string, idPrefix string, opt ...Option) *Plugin {
	opts := getOpts(opt...)
	p := &Plugin{
		Plugin: &store.Plugin{
			PluginName:  pluginName,
			IdPrefix:    idPrefix,
			ScopeId:     scope.Global.String(),
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return p
}

// TableName returns the table name for the host plugin.
func (c *Plugin) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "host_plugin"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *Plugin) SetTableName(n string) {
	c.tableName = n
}
