// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// A HostCatalog contains static hosts and static host sets. It is owned by
// a project.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to projectId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHostCatalog(ctx context.Context, projectId string, opt ...Option) (*HostCatalog, error) {
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, "static.NewHostCatalog", "no project id")
	}

	opts := getOpts(opt...)
	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			ProjectId:   projectId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
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
	return "static_host_catalog"
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

func allocCatalog() *HostCatalog {
	fresh := &HostCatalog{
		HostCatalog: &store.HostCatalog{},
	}
	return fresh
}

func newCatalogMetadata(c *HostCatalog, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.GetPublicId()},
		"resource-type":      []string{"static host catalog"},
		"op-type":            []string{op.String()},
	}
	if c.ProjectId != "" {
		metadata["project-id"] = []string{c.ProjectId}
	}
	return metadata
}
