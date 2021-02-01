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
	DefaultTargetHostSetTableName = "target_host_set"
)

type TargetHostSet struct {
	*store.TargetHostSet
	tableName string `gorm:"-"`
}

var _ db.VetForWriter = (*TargetHostSet)(nil)

// TargetHostSet creates a new in memory target host set. No options are
// currently supported.
func NewTargetHostSet(targetId, hostSetId string, _ ...Option) (*TargetHostSet, error) {
	const op = "target.NewTargetHostSet"
	if targetId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if hostSetId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing hostSetId id")
	}
	t := &TargetHostSet{
		TargetHostSet: &store.TargetHostSet{
			TargetId:  targetId,
			HostSetId: hostSetId,
		},
	}
	return t, nil
}

// allocTargetHostSet will allocate a target host set
func allocTargetHostSet() TargetHostSet {
	return TargetHostSet{
		TargetHostSet: &store.TargetHostSet{},
	}
}

// Clone creates a clone of the target host set
func (t *TargetHostSet) Clone() interface{} {
	cp := proto.Clone(t.TargetHostSet)
	return &TargetHostSet{
		TargetHostSet: cp.(*store.TargetHostSet),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the target
// host set before it's written.
func (t *TargetHostSet) VetForWrite(_ context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target.(TargetHostSet).VetForWrite"
	if opType == db.CreateOp {
		if t.TargetId == "" {
			return errors.New(errors.InvalidParameter, op, "missing target id")
		}
		if t.HostSetId == "" {
			return errors.New(errors.InvalidParameter, op, "missing host set id")
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (t *TargetHostSet) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return DefaultTargetHostSetTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *TargetHostSet) SetTableName(n string) {
	t.tableName = n
}

func (t *TargetHostSet) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{fmt.Sprintf("%s:%s", t.TargetId, t.HostSetId)},
		"resource-type":      []string{"target host set"},
		"op-type":            []string{op.String()},
	}
	return metadata
}

// TargetSet is returned from most repo operations as the target's host set.
type TargetSet struct {
	*hostStore.Set
}

// TableName returns the tablename to override the default gorm table name
func (ts *TargetSet) TableName() string {
	return "target_set"
}
