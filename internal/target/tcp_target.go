package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultTcpTableName = "target_tcp"
)

type TcpTarget struct {
	*store.TcpTarget
	tableName string `gorm:"-"`
}

var (
	_ Target                  = (*TcpTarget)(nil)
	_ db.VetForWriter         = (*TcpTarget)(nil)
	_ oplog.ReplayableMessage = (*TcpTarget)(nil)
)

// NewTcpTarget creates a new in memory tcp target.  WithName, WithDescription and
// WithDefaultPort options are supported
func NewTcpTarget(scopeId string, opt ...Option) (*TcpTarget, error) {
	const op = "target.NewTcpTarget"
	opts := getOpts(opt...)
	if scopeId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing scope id")
	}
	t := &TcpTarget{
		TcpTarget: &store.TcpTarget{
			ScopeId:                scopeId,
			Name:                   opts.withName,
			Description:            opts.withDescription,
			DefaultPort:            opts.withDefaultPort,
			SessionConnectionLimit: opts.withSessionConnectionLimit,
			SessionMaxSeconds:      opts.withSessionMaxSeconds,
			WorkerFilter:           opts.withWorkerFilter,
		},
	}
	return t, nil
}

// allocTcpTarget will allocate a tcp target
func allocTcpTarget() TcpTarget {
	return TcpTarget{
		TcpTarget: &store.TcpTarget{},
	}
}

// Clone creates a clone of the TcpTarget
func (t *TcpTarget) Clone() interface{} {
	cp := proto.Clone(t.TcpTarget)
	return &TcpTarget{
		TcpTarget: cp.(*store.TcpTarget),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the tcp target
// before it's written.
func (t *TcpTarget) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target.(TcpTarget).VetForWrite"
	if t.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if opType == db.CreateOp {
		if t.ScopeId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
		}
		if t.Name == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing name")
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (t *TcpTarget) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return DefaultTcpTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *TcpTarget) SetTableName(n string) {
	t.tableName = n
}

func (t *TcpTarget) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{t.PublicId},
		"resource-type":      []string{"tcp target"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{t.ScopeId},
	}
	return metadata
}

func (t TcpTarget) GetType() string {
	return "tcp"
}
