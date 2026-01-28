// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/alias/target/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// An Alias contains a storage alias. It is owned by a scope.
type Alias struct {
	*store.Alias
	tableName string `gorm:"-"`
}

func (al *Alias) Clone() *Alias {
	cp := proto.Clone(al.Alias)
	return &Alias{
		Alias: cp.(*store.Alias),
	}
}

// allocAlias is just easier/better than leaking the underlying type
// bits to the repo, since the repo needs to alloc this type quite often.
func allocAlias() *Alias {
	fresh := &Alias{
		Alias: &store.Alias{},
	}
	return fresh
}

// NewAlias generates a new in-memory alias. Scope and Value must be non-empty.
func NewAlias(ctx context.Context, scopeId, value string, opt ...Option) (*Alias, error) {
	const op = "target.NewAlias"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &Alias{
		Alias: &store.Alias{
			Name:          opts.withName,
			Description:   opts.withDescription,
			ScopeId:       scopeId,
			Value:         value,
			DestinationId: opts.withDestinationId,
			HostId:        opts.withHostId,
		},
	}, nil
}

// GetResourceType returns the resource type of the Alias
func (al Alias) GetResourceType() resource.Type {
	return resource.Alias
}

func (al *Alias) TableName() string {
	if al.tableName != "" {
		return al.tableName
	}
	return "alias_target"
}

func (al *Alias) SetTableName(tableName string) {
	al.tableName = tableName
}

type deletedAlias struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (al *deletedAlias) TableName() string {
	return "alias_target_deleted"
}

func newAliasMetadata(a *Alias, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.GetPublicId()},
		"resource-type":      []string{"target alias"},
		"op-type":            []string{op.String()},
		"scope_id":           []string{a.ScopeId},
	}
	return metadata
}
