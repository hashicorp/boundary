// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
)

const (
	defaultScopePolicyStoragePolicyTableName = "scope_policy_storage_policy"
)

var (
	_ oplog.ReplayableMessage = (*ScopePolicyStoragePolicy)(nil)
	_ db.VetForWriter         = (*ScopePolicyStoragePolicy)(nil)
)

// ScopePolicyStoragePolicy is used to create an hierarchy of "containers" that
// encompass the scope storage policy of an IAM resource.
type ScopePolicyStoragePolicy struct {
	*store.ScopePolicyStoragePolicy

	// tableName which is used to support overriding the table name in the db
	// and making the Scope a ReplayableMessage
	tableName string `gorm:"-"`
}

func (s *ScopePolicyStoragePolicy) GetPublicId() string {
	return s.GetScopeId()
}

// TableName returns the tablename to override the default gorm table name
func (s *ScopePolicyStoragePolicy) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultScopePolicyStoragePolicyTableName
}

// Oplog provides the oplog.Metadata for recording operations taken on a ScopePolicyStoragePolicy.
func (s *ScopePolicyStoragePolicy) Oplog(op oplog.OpType) oplog.Metadata {
	return oplog.Metadata{
		"resource-public-id": []string{s.ScopeId},
		"resource-type":      []string{"scope-policy-storage-policy"},
		"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
	}
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *ScopePolicyStoragePolicy) SetTableName(n string) {
	s.tableName = n
}

// VetForWrite implements db.VetForWrite() interface and validates the tcp target
// before it's written.
func (s *ScopePolicyStoragePolicy) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "iam.(ScopePolicyStoragePolicy).VetForWrite"
	if s.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if opType == db.CreateOp {
		if s.ScopeId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
		}
		if s.StoragePolicyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing storage policy id")
		}
	}
	return nil
}

func AllocScopePolicyStoragePolicy() ScopePolicyStoragePolicy {
	return ScopePolicyStoragePolicy{
		ScopePolicyStoragePolicy: &store.ScopePolicyStoragePolicy{},
	}
}
