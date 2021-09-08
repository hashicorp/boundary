// Package plugin provides a plugin host catalog, and plugin host set resource
// which are used to interact with a host plugin as well as a repository to
// perform CRUDL and custom actions on these resource types.
package plugin

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"google.golang.org/protobuf/proto"
)

// A HostCatalog contains plugin host sets. It is owned by
// a scope.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to a scopeId
// and pluginId. Name and description are the only valid options. All other
// options are ignored.
func NewHostCatalog(ctx context.Context, pluginId, scopeId string, opt ...Option) (*HostCatalog, error) {
	const op = "plugin.NewHostCatalog"
	opts := getOpts(opt...)
	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			PluginId:    pluginId,
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}

	if opts.withAttributes != nil {
		attrs, err := json.Marshal(opts.withAttributes)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
		}
		hc.Attributes = attrs
	}
	return hc, nil
}

func (c *HostCatalog) clone() *HostCatalog {
	cp := proto.Clone(c.HostCatalog)
	return &HostCatalog{
		HostCatalog: cp.(*store.HostCatalog),
	}
}

// TableName returns the table name for the host catalog.
func (c *HostCatalog) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "host_plugin_catalog"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *HostCatalog) SetTableName(n string) {
	c.tableName = n
}
