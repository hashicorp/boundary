// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package tcp provides a Target subtype for a TCP Target.
// Importing this package will register it with the target package and
// allow the target.Repository to support tcp.Targets.
package tcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp/store"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const (
	defaultTableName = "target_tcp"
	Subtype          = globals.Subtype("tcp")
)

// Target is a resources that represets a networked service
// that can be accessed via TCP. It is a subtype of target.Target.
type Target struct {
	*store.Target
	// Network address assigned to the Target.
	Address           string                    `json:"address,omitempty" gorm:"-"`
	tableName         string                    `gorm:"-"`
	HostSource        []target.HostSource       `gorm:"-"`
	CredentialSources []target.CredentialSource `gorm:"-"`
	Aliases           []*talias.Alias           `gorm:"-"`
}

// Ensure Target implements interfaces
var (
	_ target.Target           = (*Target)(nil)
	_ db.VetForWriter         = (*Target)(nil)
	_ oplog.ReplayableMessage = (*Target)(nil)
)

// NewTarget creates a new in memory tcp target.  WithName, WithDescription and
// WithDefaultPort options are supported
func (h targetHooks) NewTarget(ctx context.Context, projectId string, opt ...target.Option) (target.Target, error) {
	const op = "tcp.NewTarget"
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

// AllocTarget will allocate a tcp target
func (h targetHooks) AllocTarget() target.Target {
	return &Target{
		Target: &store.Target{},
	}
}

// Clone creates a clone of the Target
func (t *Target) Clone() target.Target {
	cp := proto.Clone(t.Target)
	return &Target{
		Target:            cp.(*store.Target),
		Address:           t.Address,
		HostSource:        t.HostSource,
		CredentialSources: t.CredentialSources,
		Aliases:           t.Aliases,
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the tcp target
// before it's written.
func (t *Target) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "tcp.(Target).VetForWrite"
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
	return defaultTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *Target) SetTableName(n string) {
	t.tableName = n
}

// Oplog provides the oplog.Metadata for recording operations taken on a Target.
func (t *Target) Oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{t.PublicId},
		"resource-type":      []string{"tcp target"},
		"op-type":            []string{op.String()},
		"project-id":         []string{t.ProjectId},
	}
	return metadata
}

func (t *Target) GetType() globals.Subtype {
	return Subtype
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
	return nil
}

func (t *Target) SetPublicId(ctx context.Context, publicId string) error {
	const op = "tcp.(Target).SetPublicId"
	if !strings.HasPrefix(publicId, TargetPrefix+"_") {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", publicId, TargetPrefix))
	}

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

func (t *Target) SetSessionConnectionLimit(limit int32) {
	t.SessionConnectionLimit = limit
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

func (t *Target) SetAddress(address string) {
	t.Address = address
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

func (t *Target) SetEnableSessionRecording(_ bool)                    {}
func (t *Target) SetStorageBucketId(_ string)                         {}
func (t *Target) SetProxyServerCertificate(*target.ServerCertificate) {}
