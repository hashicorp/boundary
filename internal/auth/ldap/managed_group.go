// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// managedGroupTableName defines the default table name for a Managed Group
const managedGroupTableName = "auth_ldap_managed_group"

// ManagedGroup contains an LDAP managed group. It is assigned to an LDAP AuthMethod
// and updates/deletes to that AuthMethod are cascaded to its Managed Groups.
type ManagedGroup struct {
	*store.ManagedGroup
	tableName string
}

// NewManagedGroup creates a new in memory ManagedGroup assigned to LDAP
// AuthMethod. Supported options are WithName and WithDescription.
func NewManagedGroup(ctx context.Context, authMethodId string, groupNames []string, opt ...Option) (*ManagedGroup, error) {
	const op = "ldap.NewManagedGroup"
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case len(groupNames) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing group names")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	n, err := json.Marshal(groupNames)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal group names"))
	}
	mg := &ManagedGroup{
		ManagedGroup: &store.ManagedGroup{
			AuthMethodId: authMethodId,
			Name:         opts.withName,
			Description:  opts.withDescription,
			GroupNames:   string(n),
		},
	}
	return mg, nil
}

// AllocManagedGroup makes an empty one in memory
func AllocManagedGroup() *ManagedGroup {
	return &ManagedGroup{
		ManagedGroup: &store.ManagedGroup{},
	}
}

// clone a ManagedGroup.
func (mg *ManagedGroup) clone() *ManagedGroup {
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
	return managedGroupTableName
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
func (mg *ManagedGroup) oplog(ctx context.Context, opType oplog.OpType, authMethodScopeId string) (oplog.Metadata, error) {
	const op = "ldap.(ManagedGroup).oplog"
	switch {
	case mg == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing managed group")
	case opType == oplog.OpType_OP_TYPE_UNSPECIFIED:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing op type")
	case mg.PublicId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case mg.AuthMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case authMethodScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	metadata := oplog.Metadata{
		"resource-public-id": []string{mg.PublicId},
		"resource-type":      []string{"ldap managed group"},
		"op-type":            []string{opType.String()},
		"scope-id":           []string{authMethodScopeId},
		"auth-method-id":     []string{mg.AuthMethodId},
	}
	return metadata, nil
}

type deletedManagedGroup struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedManagedGroup) TableName() string {
	return "auth_ldap_managed_group_deleted"
}
