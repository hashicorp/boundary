package plugin

import (
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
func NewHostSetMember(hostSetId, hostId string, opt ...Option) (*HostSetMember, error) {
	const op = "plugin.NewHostSetMember"
	if hostSetId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no host set id")
	}
	if hostId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no host id")
	}
	member := &HostSetMember{
		HostSetMember: &store.HostSetMember{
			SetId:  hostSetId,
			HostId: hostId,
		},
	}
	return member, nil
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
