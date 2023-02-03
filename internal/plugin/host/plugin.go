// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin/host/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

// A Plugin enables additional logic to be used by boundary.
// It is owned by a scope.
type Plugin struct {
	*store.Plugin
	tableName string `gorm:"-"`
}

// NewPlugin creates a new in memory Plugin assigned to the global scope.
// Name, Description are the only allowed option. All other options are ignored.
func NewPlugin(opt ...Option) *Plugin {
	opts := GetOpts(opt...)
	p := &Plugin{
		Plugin: &store.Plugin{
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
	return "plugin_host"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *Plugin) SetTableName(n string) {
	c.tableName = n
}

func allocPlugin() *Plugin {
	return &Plugin{
		Plugin: &store.Plugin{},
	}
}

func (c *Plugin) clone() *Plugin {
	cp := proto.Clone(c.Plugin)
	return &Plugin{
		Plugin: cp.(*store.Plugin),
	}
}

func newPluginMetadata(p *Plugin, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{p.GetPublicId()},
		"resource-type":      []string{"host plugin"},
		"op-type":            []string{op.String()},
	}
	if p.ScopeId != "" {
		metadata["scope-id"] = []string{p.ScopeId}
	}
	return metadata
}
