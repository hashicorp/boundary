// Package plugin provides a plugin host catalog, and plugin host set resource
// which are used to interact with a host plugin as well as a repository to
// perform CRUDL and custom actions on these resource types.
package plugin

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A HostCatalog contains plugin host sets. It is owned by
// a scope.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`

	secrets []byte `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to a scopeId
// and pluginId. Name and description are the only valid options. All other
// options are ignored.
func NewHostCatalog(ctx context.Context, scopeId, pluginId string, opt ...Option) (*HostCatalog, error) {
	const op = "plugin.NewHostCatalog"
	opts := getOpts(opt...)
	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			ScopeId:     scopeId,
			PluginId:    pluginId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}

	if opts.withAttributes != nil {
		attrs, err := json.Marshal(opts.withAttributes)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter), errors.WithMsg("marshaling attributes"))
		}
		hc.Attributes = attrs
	}
	if opts.withSecrets != nil {
		secrets, err := json.Marshal(opts.withSecrets)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter), errors.WithMsg("marshaling secrets"))
		}
		hc.secrets = secrets
	}
	return hc, nil
}

func allocHostCatalog() *HostCatalog {
	return &HostCatalog{
		HostCatalog: &store.HostCatalog{},
	}
}

// clone provides a deep copy of the HostCatalog.
func (c *HostCatalog) clone() *HostCatalog {
	cp := proto.Clone(c.HostCatalog)

	hc := &HostCatalog{
		HostCatalog: cp.(*store.HostCatalog),
	}
	if c.secrets != nil {
		newSecret := make([]byte, len(c.secrets))
		copy(newSecret, c.secrets)
		hc.secrets = newSecret
	}
	return hc
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

func (s *HostCatalog) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"plugin-host-catalog"},
		"op-type":            []string{op.String()},
	}
	if s.ScopeId != "" {
		metadata["scope-id"] = []string{s.ScopeId}
	}
	return metadata
}
