package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	hostStore "github.com/hashicorp/boundary/internal/host/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultTargetHostTableName = "target_host"
)

type TargetHost struct {
	*store.TargetHost
	tableName string `gorm:"-"`
}

var _ db.VetForWriter = (*TargetHost)(nil)

// TargetHostSet creates a new in memory target host set. No options are
// currently supported.
func NewTargetHost(targetId, hostId string, _ ...Option) (*TargetHost, error) {
	const op = "target.NewTargetHost"
	if targetId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if hostId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing hostId id")
	}
	t := &TargetHost{
		TargetHost: &store.TargetHost{
			TargetId: targetId,
			HostId:   hostId,
		},
	}
	return t, nil
}

// allocTargetHost will allocate a target host
func allocTargetHost() TargetHost {
	return TargetHost{
		TargetHost: &store.TargetHost{},
	}
}

// Clone creates a clone of the target host
func (t *TargetHost) Clone() interface{} {
	cp := proto.Clone(t.TargetHost)
	return &TargetHost{
		TargetHost: cp.(*store.TargetHost),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the target
// host set before it's written.
func (t *TargetHost) VetForWrite(_ context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target.(TargetHost).VetForWrite"
	if opType == db.CreateOp {
		if t.TargetId == "" {
			return errors.New(errors.InvalidParameter, op, "missing target id")
		}
		if t.HostId == "" {
			return errors.New(errors.InvalidParameter, op, "missing host id")
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (t *TargetHost) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return DefaultTargetHostTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *TargetHost) SetTableName(n string) {
	t.tableName = n
}

func (t *TargetHost) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{fmt.Sprintf("%s:%s", t.TargetId, t.HostId)},
		"resource-type":      []string{"target host"},
		"op-type":            []string{op.String()},
	}
	return metadata
}

// TargetHost is returned from most repo operations as the target's host.
type TargetHostView struct {
	*hostStore.Host
}

// TableName returns the tablename to override the default gorm table name
func (th *TargetHostView) TableName() string {
	return "target_host_view"
}
