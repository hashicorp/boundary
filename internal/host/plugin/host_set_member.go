// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
)

// A HostSetMember represents the membership of a host in a host set.
type HostSetMember struct {
	*store.HostSetMember
	tableName string `gorm:"-"`
}

// NewHostSetMember creates a new in memory HostSetMember representing the
// membership of hostId in hostSetId.
func NewHostSetMember(ctx context.Context, setId, hostId string, opt ...Option) (*HostSetMember, error) {
	const op = "plugin.NewHostSetMember"
	if setId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no set id")
	}
	if hostId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no host id")
	}
	member := &HostSetMember{
		HostSetMember: &store.HostSetMember{
			SetId:  setId,
			HostId: hostId,
		},
	}
	return member, nil
}

// VetForWrite implements db.VetForWrite() interface for host set members.
func (m *HostSetMember) VetForWrite(ctx context.Context, _ db.Reader, _ db.OpType, _ ...db.Option) error {
	const op = "plugin.(HostSetMember).VetForWrite"
	if m.SetId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing set id")
	}
	if m.HostId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing host id")
	}
	return nil
}

// TableName returns the table name for the host set.
func (m *HostSetMember) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return "host_plugin_set_member"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (m *HostSetMember) SetTableName(n string) {
	m.tableName = n
}
