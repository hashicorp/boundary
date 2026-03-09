// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// A HostSet is a collection of hosts from the set's catalog.
type HostSet struct {
	*store.HostSet
	tableName string `gorm:"-"`
}

// NewHostSet creates a new in memory HostSet assigned to catalogId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHostSet(ctx context.Context, catalogId string, opt ...Option) (*HostSet, error) {
	if catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, "static.NewHostSet", "no catalog id")
	}

	opts := getOpts(opt...)
	set := &HostSet{
		HostSet: &store.HostSet{
			CatalogId:   catalogId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return set, nil
}

// TableName returns the table name for the host set.
func (s *HostSet) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "static_host_set"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *HostSet) SetTableName(n string) {
	s.tableName = n
}

// GetResourceType returns the resource type of the HostSet
func (s *HostSet) GetResourceType() resource.Type {
	return resource.HostSet
}

func allocHostSet() *HostSet {
	return &HostSet{
		HostSet: &store.HostSet{},
	}
}

func (s *HostSet) clone() *HostSet {
	cp := proto.Clone(s.HostSet)
	return &HostSet{
		HostSet: cp.(*store.HostSet),
	}
}

func (s *HostSet) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"static-host-set"},
		"op-type":            []string{op.String()},
	}
	if s.CatalogId != "" {
		metadata["catalog-id"] = []string{s.CatalogId}
	}
	return metadata
}

func newHostSetForMembers(setId string, version uint32) *HostSet {
	return &HostSet{
		HostSet: &store.HostSet{
			PublicId: setId,
			Version:  version + 1,
		},
	}
}

type deletedHostSet struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (ds *deletedHostSet) TableName() string {
	return "static_host_set_deleted"
}
