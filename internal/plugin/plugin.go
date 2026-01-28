// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

type PluginType int

const (
	PluginTypeUnknown PluginType = 0
	PluginTypeHost    PluginType = 1
	PluginTypeStorage PluginType = 2
)

type pluginHostSupported struct {
	PublicId string `gorm:"primary_key"`
}

func (*pluginHostSupported) isPluginSupported() {}
func (*pluginHostSupported) TableName() string {
	return "plugin_host_supported"
}

type pluginStorageSupported struct {
	PublicId string `gorm:"primary_key"`
}

func (*pluginStorageSupported) isPluginSupported() {}
func (*pluginStorageSupported) TableName() string {
	return "plugin_storage_supported"
}

// pluginSupportedTable is a special type created just to insert
// plugin flags in a safe way. the only structs that implement
// this should be above. new plugins should be added above.
type pluginSupportedTable interface {
	isPluginSupported()
}

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
	return "plugin"
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
