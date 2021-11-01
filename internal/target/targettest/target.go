// Package targettest provides a test target subtype for use by the target
// package.  Note that it leverages the tcp.Target's database table to avoid
// needing schema migrations just for tests.
package targettest

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest/store"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	Subtype      = subtypes.Subtype("tcp")
	TargetPrefix = "ttcp"
)

// Target is a target.Target used for tests.
type Target struct {
	*store.Target
	tableName string `gorm:"-"`
}

var (
	_ target.Target           = (*Target)(nil)
	_ db.VetForWriter         = (*Target)(nil)
	_ oplog.ReplayableMessage = (*Target)(nil)
)

// VetForWrite implements db.VetForWrite() interface and validates the tcp target
// before it's written.
func (t *Target) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target_test.(Target).VetForWrite"
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
func (t *Target) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return "target_tcp"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *Target) SetTableName(n string) {
	t.tableName = n
}

func (t *Target) GetPublicId() string {
	return t.PublicId
}

func (t *Target) GetScopeId() string {
	return t.ScopeId
}

func (t *Target) GetDefaultPort() uint32 {
	return t.DefaultPort
}

func (t *Target) GetName() string {
	return t.Name
}

func (t *Target) GetDescription() string {
	return t.Description
}

func (t *Target) GetVersion() uint32 {
	return t.Version
}

func (t *Target) GetType() subtypes.Subtype {
	return Subtype
}

func (t *Target) GetCreateTime() *timestamp.Timestamp {
	return t.CreateTime
}

func (t *Target) GetUpdateTime() *timestamp.Timestamp {
	return t.UpdateTime
}

func (t *Target) GetSessionMaxSeconds() uint32 {
	return t.SessionMaxSeconds
}

func (t *Target) GetSessionConnectionLimit() int32 {
	return t.SessionConnectionLimit
}

func (t *Target) GetWorkerFilter() string {
	return t.WorkerFilter
}

func (t *Target) Clone() target.Target {
	cp := proto.Clone(t.Target)
	return &Target{
		Target: cp.(*store.Target),
	}
}

func (t *Target) SetPublicId(_ context.Context, publicId string) error {
	t.PublicId = publicId
	return nil
}

func (t *Target) SetScopeId(scopeId string) {
	t.ScopeId = scopeId
}

func (t *Target) SetName(name string) {
	t.Name = name
}

func (t *Target) SetDescription(description string) {
	t.Description = description
}

func (t *Target) SetVersion(v uint32) {
	t.Version = v
}

func (t *Target) SetDefaultPort(port uint32) {
	t.DefaultPort = port
}

func (t *Target) SetCreateTime(ts *timestamp.Timestamp) {
	t.CreateTime = ts
}

func (t *Target) SetUpdateTime(ts *timestamp.Timestamp) {
	t.UpdateTime = ts
}

func (t *Target) SetSessionMaxSeconds(s uint32) {
	t.SessionMaxSeconds = s
}

func (t *Target) SetSessionConnectionLimit(l int32) {
	t.SessionConnectionLimit = l
}

func (t *Target) SetWorkerFilter(f string) {
	t.WorkerFilter = f
}

func (t *Target) Oplog(op oplog.OpType) oplog.Metadata {
	return oplog.Metadata{
		"resource-public-id": []string{t.PublicId},
		"resource-type":      []string{"tcp target"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{t.ScopeId},
	}
}

// Alloc creates an in-memory Target.
func Alloc() target.Target {
	return &Target{
		Target: &store.Target{},
	}
}

// Vet checks that the given Target is a targettest.Target and that it is not nil.
func Vet(ctx context.Context, t target.Target) error {
	const op = "targettest.Vet"

	tt, ok := t.(*Target)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "target is not a tcp.Target")
	}

	if tt == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target")
	}

	if tt.Target == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target store")
	}
	return nil
}

// VetCredentialLibraries allows for any CredentialLibraries.
func VetCredentialLibraries(_ context.Context, _ []*target.CredentialLibrary) error {
	return nil
}

// New creates a targettest.Target.
func New(scopeId string, opt ...target.Option) (*Target, error) {
	const op = "target_test.New"
	opts := target.GetOpts(opt...)
	if scopeId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing scope id")
	}
	t := &Target{
		Target: &store.Target{
			ScopeId:                scopeId,
			Name:                   opts.WithName,
			Description:            opts.WithDescription,
			DefaultPort:            opts.WithDefaultPort,
			SessionConnectionLimit: opts.WithSessionConnectionLimit,
			SessionMaxSeconds:      opts.WithSessionMaxSeconds,
			WorkerFilter:           opts.WithWorkerFilter,
		},
	}
	return t, nil
}

// TestNewTestTarget is a test helper for creating a targettest.Target.
func TestNewTestTarget(t *testing.T, conn *db.DB, scopeId, name string, opt ...target.Option) *Target {
	t.Helper()
	opt = append(opt, target.WithName(name))
	opts := target.GetOpts(opt...)
	require := require.New(t)
	rw := db.New(conn)
	tar, err := New(scopeId, opt...)
	require.NoError(err)
	id, err := db.NewPublicId(TargetPrefix)
	require.NoError(err)
	tar.PublicId = id
	err = rw.Create(context.Background(), tar)
	require.NoError(err)

	if len(opts.WithHostSources) > 0 {
		newHostSets := make([]interface{}, 0, len(opts.WithHostSources))
		for _, s := range opts.WithHostSources {
			hostSet, err := target.NewTargetHostSet(tar.PublicId, s)
			require.NoError(err)
			newHostSets = append(newHostSets, hostSet)
		}
		err := rw.CreateItems(context.Background(), newHostSets)
		require.NoError(err)
	}
	if len(opts.WithCredentialLibraries) > 0 {
		newCredLibs := make([]interface{}, 0, len(opts.WithCredentialLibraries))
		for _, cl := range opts.WithCredentialLibraries {
			cl.TargetId = tar.PublicId
			newCredLibs = append(newCredLibs, cl)
		}
		err := rw.CreateItems(context.Background(), newCredLibs)
		require.NoError(err)
	}
	return tar
}
