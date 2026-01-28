// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package plugin provides a plugin host catalog, and plugin host set resource
// which are used to interact with a host plugin as well as a repository to
// perform CRUDL and custom actions on these resource types.
package plugin

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin"
	plgstore "github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// A HostCatalog contains plugin host sets. It is owned by
// a project.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`

	Secrets *structpb.Struct `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to a projectId
// and pluginId. WithName, WithDescription, WithSecretsHmac, WithAttributes,
// WithSecrets and WithWorkerFilter are the only valid options. All other
// options are ignored.
func NewHostCatalog(ctx context.Context, projectId, pluginId string, opt ...Option) (*HostCatalog, error) {
	const op = "plugin.NewHostCatalog"
	opts := getOpts(opt...)

	attrs, err := proto.Marshal(opts.withAttributes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}

	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			ProjectId:    projectId,
			PluginId:     pluginId,
			Name:         opts.withName,
			Description:  opts.withDescription,
			Attributes:   attrs,
			SecretsHmac:  opts.withSecretsHmac,
			WorkerFilter: opts.withWorkerFilter,
		},
		Secrets: opts.withSecrets,
	}
	return hc, nil
}

func allocHostCatalog() *HostCatalog {
	return &HostCatalog{
		HostCatalog: &store.HostCatalog{},
	}
}

// hmacSecrets before writing it to the db
func (c *HostCatalog) hmacSecrets(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "plugin.(HostCatalog).hmacSecrets"
	if c.Secrets == nil {
		c.SecretsHmac = nil
		return nil
	}
	secretsMap := c.Secrets.AsMap()
	if len(secretsMap) == 0 {
		c.SecretsHmac = nil
		return nil
	}
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	// Go's JSON encoding is stable (that is, it alphabetizes keys) so it's a
	// good option to produce an HMAC-able string.
	jsonSecrets, err := json.Marshal(secretsMap)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Code(errors.Encryption)))
	}
	hm, err := crypto.HmacSha256(ctx, jsonSecrets, cipher, []byte(c.PublicId), nil)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Code(errors.Encryption)))
	}
	c.SecretsHmac = []byte(hm)
	return nil
}

// clone provides a deep copy of the HostCatalog with the exception of the
// secret.  The secret shallow copied.
func (c *HostCatalog) clone() *HostCatalog {
	cp := proto.Clone(c.HostCatalog)
	newSecret := proto.Clone(c.Secrets)

	hc := &HostCatalog{
		HostCatalog: cp.(*store.HostCatalog),
		Secrets:     newSecret.(*structpb.Struct),
	}
	// proto.Clone will convert slices with length and capacity of 0 to nil.
	// Fix this since gorm treats empty slices differently than nil.
	if c.Attributes != nil && len(c.Attributes) == 0 && hc.Attributes == nil {
		hc.Attributes = []byte{}
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

// GetResourceType returns the resource type of the HostCatalog
func (c *HostCatalog) GetResourceType() resource.Type {
	return resource.HostCatalog
}

func (c *HostCatalog) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"plugin-host-catalog"},
		"op-type":            []string{op.String()},
	}
	if c.ProjectId != "" {
		metadata["project-id"] = []string{c.ProjectId}
	}
	return metadata
}

// TODO: Refactor repository (catalogAgg + getPlugin) uses to just use
// catalogAgg + catalogAgg.plugin().
type catalogAgg struct {
	PublicId            string `gorm:"primary_key"`
	ProjectId           string
	PluginId            string
	Name                string
	Description         string
	CreateTime          *timestamp.Timestamp
	UpdateTime          *timestamp.Timestamp
	Version             uint32
	SecretsHmac         []byte
	Attributes          []byte
	WorkerFilter        string
	Secret              []byte
	KeyId               string
	PersistedCreateTime *timestamp.Timestamp
	PersistedUpdateTime *timestamp.Timestamp
	PluginScopeId       string
	PluginName          string
	PluginDescription   string
	PluginCreateTime    *timestamp.Timestamp
	PluginUpdateTime    *timestamp.Timestamp
	PluginVersion       uint32
}

func (agg *catalogAgg) toCatalogAndPersisted() (*HostCatalog, *HostCatalogSecret) {
	if agg == nil {
		return nil, nil
	}
	c := allocHostCatalog()
	c.PublicId = agg.PublicId
	c.ProjectId = agg.ProjectId
	c.PluginId = agg.PluginId
	c.Name = agg.Name
	c.Description = agg.Description
	c.CreateTime = agg.CreateTime
	c.UpdateTime = agg.UpdateTime
	c.Version = agg.Version
	c.SecretsHmac = agg.SecretsHmac
	c.Attributes = agg.Attributes
	c.WorkerFilter = agg.WorkerFilter

	var s *HostCatalogSecret
	if len(agg.Secret) > 0 {
		s = allocHostCatalogSecret()
		s.CatalogId = agg.PublicId
		s.CtSecret = agg.Secret
		s.KeyId = agg.KeyId
		s.CreateTime = agg.PersistedCreateTime
		s.UpdateTime = agg.PersistedUpdateTime
	}
	return c, s
}

func (agg *catalogAgg) plugin() *plugin.Plugin {
	return &plugin.Plugin{
		Plugin: &plgstore.Plugin{
			PublicId:    agg.PluginId,
			ScopeId:     agg.PluginScopeId,
			Name:        agg.PluginName,
			Description: agg.PluginDescription,
			CreateTime:  agg.PluginCreateTime,
			UpdateTime:  agg.PluginUpdateTime,
			Version:     agg.PluginVersion,
		},
	}
}

// TableName returns the table name for gorm
func (agg *catalogAgg) TableName() string {
	return "host_plugin_catalog_with_secret"
}

func (agg *catalogAgg) GetPublicId() string {
	return agg.PublicId
}
