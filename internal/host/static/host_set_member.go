package static

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static/store"
)

// A HostSetMember represents the membership of a host in a host set.
type HostSetMember struct {
	*store.HostSetMember
	tableName string `gorm:"-"`
}

// NewHostSetMember creates a new in memory HostSetMember representing the
// membership of hostId in hostSetId.
func NewHostSetMember(hostSetId, hostId string, opt ...Option) (*HostSetMember, error) {
	if hostSetId == "" {
		return nil, fmt.Errorf("new: static host set member: no host set id: %w", db.ErrInvalidParameter)
	}
	if hostId == "" {
		return nil, fmt.Errorf("new: static host set member: no host id: %w", db.ErrInvalidParameter)
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
	return "static_host_set_member"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (m *HostSetMember) SetTableName(n string) {
	m.tableName = n
}
