// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package targettest provides a test target subtype for use by the target
// package.  Note that it leverages the tcp.Target's database table to avoid
// needing schema migrations just for tests.
package targettest

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest/store"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	Subtype = globals.Subtype("tcp")
)

// Target is a target.Target used for tests.
type Target struct {
	*store.Target
	Address           string                    `gorm:"-"`
	tableName         string                    `gorm:"-"`
	HostSource        []target.HostSource       `gorm:"-"`
	CredentialSources []target.CredentialSource `gorm:"-"`
	Aliases           []*talias.Alias           `gorm:"-"`
	ServerCert        *target.ServerCertificate `gorm:"-"`
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
		if t.ProjectId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing project id")
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

func (t *Target) GetProjectId() string {
	return t.ProjectId
}

func (t *Target) GetDefaultPort() uint32 {
	return t.DefaultPort
}

func (t *Target) GetDefaultClientPort() uint32 {
	return t.DefaultClientPort
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

func (t *Target) GetType() globals.Subtype {
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

func (t *Target) GetEgressWorkerFilter() string {
	return t.EgressWorkerFilter
}

func (t *Target) GetIngressWorkerFilter() string {
	return t.IngressWorkerFilter
}

func (t *Target) GetAddress() string {
	return t.Address
}

func (t *Target) GetAliases() []*talias.Alias {
	return t.Aliases
}

func (t *Target) GetHostSources() []target.HostSource {
	return t.HostSource
}

func (t *Target) GetCredentialSources() []target.CredentialSource {
	return t.CredentialSources
}

func (t *Target) GetEnableSessionRecording() bool {
	return false
}

func (t *Target) GetStorageBucketId() string {
	return ""
}

func (t *Target) GetProxyServerCertificate() *target.ServerCertificate {
	return t.ServerCert
}

func (t *Target) Clone() target.Target {
	cp := proto.Clone(t.Target)
	return &Target{
		Address:           t.Address,
		Target:            cp.(*store.Target),
		HostSource:        t.HostSource,
		CredentialSources: t.CredentialSources,
	}
}

func (t *Target) SetPublicId(_ context.Context, publicId string) error {
	t.PublicId = publicId
	return nil
}

func (t *Target) SetProjectId(projectId string) {
	t.ProjectId = projectId
}

func (t *Target) SetName(name string) {
	t.Name = name
}

func (t *Target) SetDescription(description string) {
	t.Description = description
}

// GetResourceType returns the resource type of the Target
func (t *Target) GetResourceType() resource.Type {
	return resource.Target
}

func (t *Target) SetVersion(v uint32) {
	t.Version = v
}

func (t *Target) SetDefaultPort(port uint32) {
	t.DefaultPort = port
}

func (t *Target) SetDefaultClientPort(port uint32) {
	t.DefaultClientPort = port
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

func (t *Target) SetWorkerFilter(filter string) {
	t.WorkerFilter = filter
}

func (t *Target) SetEgressWorkerFilter(filter string) {
	t.EgressWorkerFilter = filter
}

func (t *Target) SetIngressWorkerFilter(filter string) {
	t.IngressWorkerFilter = filter
}

func (t *Target) SetAddress(a string) {
	t.Address = a
}

func (t *Target) SetAliases(aliases []*talias.Alias) {
	t.Aliases = aliases
}

func (t *Target) SetHostSources(sources []target.HostSource) {
	t.HostSource = sources
}

func (t *Target) SetCredentialSources(sources []target.CredentialSource) {
	t.CredentialSources = sources
}

func (t *Target) SetEnableSessionRecording(_ bool) {}

func (t *Target) SetStorageBucketId(_ string) {}

func (t *Target) SetProxyServerCertificate(sc *target.ServerCertificate) {
	t.ServerCert = sc
}

func (t *Target) Oplog(op oplog.OpType) oplog.Metadata {
	return oplog.Metadata{
		"resource-public-id": []string{t.PublicId},
		"resource-type":      []string{"tcp target"},
		"op-type":            []string{op.String()},
		"project-id":         []string{t.ProjectId},
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

// vet validates that the given Target is a targettest.Target and that it
// has a Target store.
func VetForUpdate(ctx context.Context, t target.Target, paths []string) error {
	const op = "targettest.vetForUpdate"

	tt, ok := t.(*Target)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "target is not a tcp.Target")
	}

	switch {
	case tt == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing target")
	case tt.Target == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing target store")
	}

	for _, f := range paths {
		if strings.EqualFold("defaultport", f) && tt.GetDefaultPort() == 0 {
			return errors.New(ctx, errors.InvalidParameter, op, "clearing or setting default port to zero")
		}
	}

	return nil
}

// VetCredentialSources allows for any CredentialLibraries.
func VetCredentialSources(_ context.Context, _ []*target.CredentialLibrary, _ []*target.StaticCredential) error {
	return nil
}

// New creates a targettest.Target.
func New(ctx context.Context, projectId string, opt ...target.Option) (target.Target, error) {
	const op = "target_test.New"
	opts := target.GetOpts(opt...)
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	t := &Target{
		Target: &store.Target{
			ProjectId:              projectId,
			Name:                   opts.WithName,
			Description:            opts.WithDescription,
			DefaultPort:            opts.WithDefaultPort,
			DefaultClientPort:      opts.WithDefaultClientPort,
			SessionConnectionLimit: opts.WithSessionConnectionLimit,
			SessionMaxSeconds:      opts.WithSessionMaxSeconds,
			WorkerFilter:           opts.WithWorkerFilter,
			EgressWorkerFilter:     opts.WithEgressWorkerFilter,
			IngressWorkerFilter:    opts.WithIngressWorkerFilter,
		},
		Address: opts.WithAddress,
	}
	return t, nil
}

// TestNewTestTarget is a test helper for creating a targettest.Target.
func TestNewTestTarget(ctx context.Context, t *testing.T, conn *db.DB, projectId, name string, opt ...target.Option) target.Target {
	t.Helper()
	opt = append(opt, target.WithName(name))
	opts := target.GetOpts(opt...)
	require := require.New(t)
	rw := db.New(conn)
	tar, err := New(ctx, projectId, opt...)
	require.NoError(err)
	id, err := db.NewPublicId(ctx, globals.TcpTargetPrefix)
	require.NoError(err)
	tar.SetPublicId(ctx, id)
	err = rw.Create(context.Background(), tar)
	require.NoError(err)

	if len(opts.WithHostSources) > 0 {
		newHostSets := make([]*target.TargetHostSet, 0, len(opts.WithHostSources))
		for _, s := range opts.WithHostSources {
			hostSet, err := target.NewTargetHostSet(ctx, tar.GetPublicId(), s)
			require.NoError(err)
			newHostSets = append(newHostSets, hostSet)
		}
		err := rw.CreateItems(context.Background(), newHostSets)
		require.NoError(err)
	}
	if len(opts.WithCredentialLibraries) > 0 {
		newCredLibs := make([]*target.CredentialLibrary, 0, len(opts.WithCredentialLibraries))
		for _, cl := range opts.WithCredentialLibraries {
			cl.TargetId = tar.GetPublicId()
			newCredLibs = append(newCredLibs, cl)
		}
		err := rw.CreateItems(context.Background(), newCredLibs)
		require.NoError(err)
	}
	if len(opts.WithAddress) != 0 {
		addr := target.TestNewTargetAddress(id, opts.WithAddress)
		err := rw.Create(ctx, addr)
		require.NoError(err)
	}
	return tar
}
