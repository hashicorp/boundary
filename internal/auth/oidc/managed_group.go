// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-bexpr"
	"google.golang.org/protobuf/proto"
)

// defaultManagedGroupTableName defines the default table name for a Managed Group
const defaultManagedGroupTableName = "auth_oidc_managed_group"

// ManagedGroup contains an OIDC managed group. It is assigned to an OIDC AuthMethod
// and updates/deletes to that AuthMethod are cascaded to its Managed Groups.
type ManagedGroup struct {
	*store.ManagedGroup
	tableName string
}

// NewManagedGroup creates a new in memory ManagedGroup assigned to OIDC
// AuthMethod. Supported options are withName and withDescription.
func NewManagedGroup(ctx context.Context, authMethodId string, filter string, opt ...Option) (*ManagedGroup, error) {
	const op = "oidc.NewManagedGroup"
	opts := getOpts(opt...)
	mg := &ManagedGroup{
		ManagedGroup: &store.ManagedGroup{
			AuthMethodId: authMethodId,
			Name:         opts.withName,
			Description:  opts.withDescription,
			Filter:       filter,
		},
	}
	if err := mg.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped.
	}

	return mg, nil
}

// validate the Managed Group.  On success, it will return nil.
func (mg *ManagedGroup) validate(ctx context.Context, caller errors.Op) error {
	if mg.AuthMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing auth method id")
	}
	if mg.Filter == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing filter")
	}
	if _, err := bexpr.CreateEvaluator(mg.Filter); err != nil {
		return errors.New(ctx, errors.InvalidParameter, caller, "error evaluating filter expression", errors.WithWrap(err))
	}

	return nil
}

// AllocManagedGroup makes an empty one in memory
func AllocManagedGroup() *ManagedGroup {
	return &ManagedGroup{
		ManagedGroup: &store.ManagedGroup{},
	}
}

// Clone a ManagedGroup.
func (mg *ManagedGroup) Clone() *ManagedGroup {
	cp := proto.Clone(mg.ManagedGroup)
	return &ManagedGroup{
		ManagedGroup: cp.(*store.ManagedGroup),
	}
}

// TableName returns the table name.
func (mg *ManagedGroup) TableName() string {
	if mg.tableName != "" {
		return mg.tableName
	}
	return defaultManagedGroupTableName
}

// SetTableName sets the table name.
func (mg *ManagedGroup) SetTableName(n string) {
	mg.tableName = n
}

// GetResourceType returns the resource type of the ManagedGroup
func (mg *ManagedGroup) GetResourceType() resource.Type {
	return resource.ManagedGroup
}

// oplog will create oplog metadata for the ManagedGroup.
func (mg *ManagedGroup) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{mg.GetPublicId()},
		"resource-type":      []string{"oidc managed group"},
		"op-type":            []string{op.String()},
	}
	if mg.AuthMethodId != "" {
		metadata["auth-method-id"] = []string{mg.AuthMethodId}
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}

type deletedManagedGroup struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedManagedGroup) TableName() string {
	return "auth_oidc_managed_group_deleted"
}
