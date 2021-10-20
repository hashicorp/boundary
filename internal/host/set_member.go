package host

import (
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/store"
	"google.golang.org/protobuf/proto"
)

// A SetMember represents the membership of a host in a host set.
type SetMember struct {
	*store.SetMember
	tableName string `gorm:"-"`
}

// NewSetMember creates a new in memory SetMember representing the
// membership of hostId in hostSetId.
func NewSetMember(hostSetId, hostId string, opt ...Option) (*SetMember, error) {
	const op = "host.NewSetMember"
	if hostSetId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no host set id")
	}
	if hostId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no host id")
	}
	member := &SetMember{
		SetMember: &store.SetMember{
			SetId:  hostSetId,
			HostId: hostId,
		},
	}
	return member, nil
}

// TableName returns the table name for the host set.
func (m *SetMember) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return "host_set_member"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (m *SetMember) SetTableName(n string) {
	m.tableName = n
}

func (m *SetMember) Clone() *SetMember {
	return &SetMember{
		SetMember: proto.Clone(m.SetMember).(*store.SetMember),
		tableName: m.tableName,
	}
}
