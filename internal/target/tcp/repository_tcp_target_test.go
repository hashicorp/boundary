// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)

	ctx := context.Background()
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
	static.TestSets(t, conn, cats[0].GetPublicId(), 2)

	cs := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, 2)

	type args struct {
		target target.Target
		opt    []target.Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantAddress string
		wantIsError errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("valid-org"),
						target.WithDescription("valid-org"),
						target.WithDefaultPort(uint32(22)))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr: false,
		},
		{
			name: "with-dns-name",
			args: args{
				target: func() *tcp.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-dns-name"),
						target.WithDescription("with-dns-name"),
						target.WithDefaultPort(uint32(22)),
						target.WithAddress("www.google.com"),
					)
					require.NoError(t, err)
					return target.(*tcp.Target)
				}(),
			},
			wantErr:     false,
			wantAddress: "www.google.com",
		},
		{
			name: "with-ipv4-address",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-ipv4-address"),
						target.WithDescription("with-ipv4-address"),
						target.WithDefaultPort(80),
						target.WithAddress("8.8.8.8"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     false,
			wantAddress: "8.8.8.8",
		},
		{
			name: "with-invalid-ipv4-address-with-port",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-invalid-ipv4-address-with-port"),
						target.WithDescription("with-invalid-ipv4-address-with-port"),
						target.WithDefaultPort(80),
						target.WithAddress("8.8.8.8:80"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidAddress,
		},
		{
			name: "with-abbreviated-ipv6-address",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-abbreviated-ipv6-address"),
						target.WithDescription("with-abbreviated-ipv6-address"),
						target.WithDefaultPort(80),
						target.WithAddress("2001:BEEF:4860::8888"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     false,
			wantAddress: "2001:beef:4860::8888",
		},
		{
			name: "with-ipv6-address",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-ipv6-address"),
						target.WithDescription("with-ipv6-address"),
						target.WithDefaultPort(80),
						target.WithAddress("2001:BEEF:4860:0:0:0:0:8888"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     false,
			wantAddress: "2001:beef:4860::8888",
		},
		{
			name: "with-abbreviated-[ipv6]-address",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-abbreviated-[ipv6]-address"),
						target.WithDescription("with-abbreviated-[ipv6]-address"),
						target.WithDefaultPort(80),
						target.WithAddress("[2001:4860:4860::8888]"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidAddress,
		},
		{
			name: "with-invalid-abbreviated-[ipv6]-address-with-port",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-invalid-abbreviated-[ipv6]-address-with-port"),
						target.WithDescription("with-invalid-abbreviated-[ipv6]-address-with-port"),
						target.WithDefaultPort(80),
						target.WithAddress("[2001:4860:4860::8888]:80"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidAddress,
		},
		{
			name: "with-[ipv6]-address",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-[ipv6]-address"),
						target.WithDescription("with-[ipv6]-address"),
						target.WithDefaultPort(80),
						target.WithAddress("[2001:4860:4860:0:0:0:0:8888]"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidAddress,
		},
		{
			name: "with-invalid-[ipv6]-address-with-port",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-invalid-[ipv6]-address-with-port"),
						target.WithDescription("with-invalid-[ipv6]-address-with-port"),
						target.WithDefaultPort(80),
						target.WithAddress("[2001:4860:4860:0:0:0:0:8888]:80"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidAddress,
		},
		{
			name: "with-address-whitespace",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("with-address-whitespace"),
						target.WithDescription("with-address-whitespace"),
						target.WithDefaultPort(80),
						target.WithAddress(" 8.8.8.8 "))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     false,
			wantAddress: "8.8.8.8",
		},
		{
			name: "nil-target",
			args: args{
				target: nil,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "nil-target-store",
			args: args{
				target: func() *tcp.Target {
					target := &tcp.Target{}
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "public-id-not-empty",
			args: args{
				target: func() target.Target {
					tar, err := target.New(
						ctx,
						tcp.Subtype,
						proj.PublicId,
						target.WithName("valid-org"),
						target.WithDescription("valid-org"),
						target.WithDefaultPort(uint32(22)),
					)
					require.NoError(t, err)
					id, err := db.NewPublicId(ctx, globals.TcpTargetPrefix)
					require.NoError(t, err)
					tar.SetPublicId(ctx, id)
					return tar
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-project-id",
			args: args{
				target: func() target.Target {
					tar, err := target.New(
						ctx,
						tcp.Subtype,
						proj.PublicId,
						target.WithName("empty-project-id"),
					)
					require.NoError(t, err)
					tar.SetProjectId("")
					return tar
				}(),
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "valid-with-egress-filter",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("valid-egress-filter"),
						target.WithDescription("valid-org"),
						target.WithDefaultPort(uint32(22)),
						target.WithEgressWorkerFilter("test-filter"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr: false,
		},
		{
			name: "deprecated-worker-filter",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("bad-worker-filter"),
						target.WithDescription("valid-org"),
						target.WithDefaultPort(uint32(22)),
						target.WithWorkerFilter("test-filter"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.Exception,
		},
		{
			name: "invalid-setting-egress-and-worker-filter",
			args: args{
				target: func() target.Target {
					target, err := target.New(ctx, tcp.Subtype, proj.PublicId,
						target.WithName("bad-filters"),
						target.WithDescription("valid-org"),
						target.WithDefaultPort(uint32(22)),
						target.WithWorkerFilter("test-filter"),
						target.WithEgressWorkerFilter("test-filter"))
					require.NoError(t, err)
					return target
				}(),
			},
			wantErr:     true,
			wantIsError: errors.Exception,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tar, err := repo.CreateTarget(context.Background(), tt.args.target, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(tar)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			require.NoError(err)
			assert.NotNil(tar.GetPublicId())

			hostSources := tar.GetHostSources()
			credSources := tar.GetCredentialSources()

			foundTarget, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
			foundHostSources := foundTarget.GetHostSources()
			foundCredLibs := foundTarget.GetCredentialSources()

			assert.NoError(err)
			if len(tt.wantAddress) != 0 {
				assert.Equal(tt.wantAddress, tar.GetAddress())
			} else {
				assert.Equal(tt.args.target.GetAddress(), tar.GetAddress())
			}
			assert.True(proto.Equal(tar.(*tcp.Target), foundTarget.(*tcp.Target)))
			assert.Equal(hostSources, foundHostSources)
			assert.Equal(credSources, foundCredLibs)

			err = db.TestVerifyOplog(t, rw, tar.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			// TODO (jimlambrt 9/2020) - unfortunately, we can currently
			// test to make sure that the oplog entry for a target host sets
			// create exist because the db.TestVerifyOplog doesn't really
			// support that level of testing and the previous call to
			// CreateTarget would create an oplog entry for the
			// create on the target even if no host sets were added.   Once
			// TestVerifyOplog supports the appropriate granularity, we should
			// add an appropriate assert.
		})
	}

	t.Run("create with aliases", func(t *testing.T) {
		newAlias1, err := talias.NewAlias(context.Background(), "global", "alias1", talias.WithHostId("hst_1234567890"))
		require.NoError(t, err)
		newAlias2, err := talias.NewAlias(context.Background(), "global", "alias2", talias.WithHostId("hst_0987654321"))
		require.NoError(t, err)

		tar, err := target.New(ctx, tcp.Subtype, proj.PublicId,
			target.WithName("create-with-alias"),
			target.WithDescription("create-with-alias"),
			target.WithDefaultPort(uint32(22)))
		require.NoError(t, err)
		tar, err = repo.CreateTarget(context.Background(), tar, target.WithAliases([]*talias.Alias{newAlias1, newAlias2}))
		require.NoError(t, err)
		assert.NotNil(t, tar)
		assert.Len(t, tar.GetAliases(), 2)
		assert.NotEmpty(t, tar.GetAliases()[0].GetPublicId())
		assert.NotEmpty(t, tar.GetAliases()[1].GetPublicId())
		assert.NotZero(t, tar.GetAliases()[0].GetCreateTime())
		assert.NotZero(t, tar.GetAliases()[1].GetCreateTime())
		assert.Contains(t, []string{newAlias1.GetValue(), newAlias2.GetValue()}, tar.GetAliases()[0].GetValue())
		assert.Contains(t, []string{newAlias1.GetValue(), newAlias2.GetValue()}, tar.GetAliases()[1].GetValue())
		assert.Contains(t, []string{newAlias1.GetHostId(), newAlias2.GetHostId()}, tar.GetAliases()[0].GetHostId())
		assert.Contains(t, []string{newAlias1.GetHostId(), newAlias2.GetHostId()}, tar.GetAliases()[1].GetHostId())
	})

	t.Run("create an invalid aliases", func(t *testing.T) {
		invalidAlias, err := talias.NewAlias(context.Background(), "global", "invalid_alias")
		require.NoError(t, err)

		tar, err := target.New(ctx, tcp.Subtype, proj.PublicId,
			target.WithName("create-with-invalid-alias"),
			target.WithDescription("create-with-invalid-alias"),
			target.WithDefaultPort(uint32(22)))
		require.NoError(t, err)
		tar, err = repo.CreateTarget(context.Background(), tar, target.WithAliases([]*talias.Alias{invalidAlias}))
		require.Error(t, err)
		require.Nil(t, tar)
	})

	t.Run("create with duplicate aliases", func(t *testing.T) {
		dupAlias, err := talias.NewAlias(context.Background(), "global", "dup-alias")
		require.NoError(t, err)

		tar, err := target.New(ctx, tcp.Subtype, proj.PublicId,
			target.WithName("create-with-duplicate-alias"),
			target.WithDescription("create-with-duplicate-alias"),
			target.WithDefaultPort(uint32(22)))
		require.NoError(t, err)
		tar, err = repo.CreateTarget(context.Background(), tar, target.WithAliases([]*talias.Alias{dupAlias, dupAlias}))
		require.Error(t, err)
		require.Nil(t, tar)
	})
}

func TestRepository_UpdateTcpTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)

	repo, err := target.NewRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)
	id := tcp.TestId(t)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	pubId := func(s string) *string { return &s }

	type args struct {
		name           string
		description    string
		address        string
		port           uint32
		fieldMaskPaths []string
		opt            []target.Option
		ProjectId      string
		PublicId       *string
	}
	tests := []struct {
		name            string
		newProjectId    string
		newName         string
		newTargetOpts   []target.Option
		args            args
		wantRowsUpdate  int
		wantErr         bool
		wantErrMsg      string
		wantIsError     errors.Code
		wantDup         bool
		wantHostSources bool
		wantAddress     string
	}{
		{
			name: "valid",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: true,
		},
		{
			name: "valid-ipv4-address",
			args: args{
				name:           "valid-ipv4-address" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "8.8.8.8",
			},
			newProjectId:    proj.PublicId,
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: false,
			wantAddress:     "8.8.8.8",
		},
		{
			name: "invalid-ipv4-address-with-port",
			args: args{
				name:           "invalid-ipv4-address-with-port" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "8.8.8.8:80",
			},
			newProjectId: proj.PublicId,
			wantErr:      true,
			wantIsError:  errors.InvalidAddress,
			wantErrMsg:   "invalid address",
		},
		{
			name: "valid-abbreviated-ipv6-address",
			args: args{
				name:           "valid-abbreviated-ipv6-address" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "2001:BEEF:4860::8888",
			},
			newProjectId:    proj.PublicId,
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: false,
			wantAddress:     "2001:beef:4860::8888",
		},
		{
			name: "valid-ipv6-address",
			args: args{
				name:           "valid-ipv6-address" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "2001:BEEF:4860:0:0:0:0:8888",
			},
			newProjectId:    proj.PublicId,
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: false,
			wantAddress:     "2001:beef:4860::8888",
		},
		{
			name: "valid-abbreviated-[ipv6]-address",
			args: args{
				name:           "valid-abbreviated-[ipv6]-address" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "[2001:4860:4860::8888]",
			},
			newProjectId: proj.PublicId,
			wantErr:      true,
			wantIsError:  errors.InvalidAddress,
			wantErrMsg:   "invalid address",
		},
		{
			name: "invalid-abbreviated-[ipv6]-address-with-port",
			args: args{
				name:           "invalid-abbreviated-[ipv6]-address-with-port" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "[2001:4860:4860::8888]:80",
			},
			newProjectId: proj.PublicId,
			wantErr:      true,
			wantIsError:  errors.InvalidAddress,
			wantErrMsg:   "invalid address",
		},
		{
			name: "valid-[ipv6]-address",
			args: args{
				name:           "valid-[ipv6]-address" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "[2001:4860:4860:0:0:0:0:8888]",
			},
			newProjectId: proj.PublicId,
			wantErr:      true,
			wantIsError:  errors.InvalidAddress,
			wantErrMsg:   "invalid address",
		},
		{
			name: "invalid-[ipv6]-address-with-port",
			args: args{
				name:           "invalid-[ipv6]-address-with-port" + id,
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
				address:        "[2001:4860:4860:0:0:0:0:8888]:80",
			},
			newProjectId: proj.PublicId,
			wantErr:      true,
			wantIsError:  errors.InvalidAddress,
			wantErrMsg:   "invalid address",
		},
		{
			name: "null-address",
			args: args{
				fieldMaskPaths: []string{"Address"},
				ProjectId:      proj.PublicId,
				address:        "null",
			},
			newProjectId:    proj.PublicId,
			newTargetOpts:   []target.Option{target.WithAddress("8.8.8.8")},
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: false,
		},
		{
			name: "address-with-whitespace",
			args: args{
				fieldMaskPaths: []string{"Address"},
				ProjectId:      proj.PublicId,
				address:        " 127.0.0.1 ",
			},
			newProjectId:    proj.PublicId,
			newTargetOpts:   []target.Option{target.WithAddress("10.0.0.1")},
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: false,
			wantAddress:     "127.0.0.1",
		},
		{
			name: "delete-address",
			args: args{
				fieldMaskPaths: []string{"Address"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			newTargetOpts:   []target.Option{target.WithAddress("8.8.8.8")},
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: false,
		},
		{
			name: "host-source-mutually-exclusive-relationship",
			args: args{
				name:           "invalid-address" + id,
				address:        "8.8.8.8",
				fieldMaskPaths: []string{"Name", "Address"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantErrMsg:      "unable to set address because one or more host sources is assigned to the given target",
			wantRowsUpdate:  0,
			wantHostSources: true,
		},
		{
			name: "valid-no-op",
			args: args{
				name:           "valid-no-op" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			newName:         "valid-no-op" + id,
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: true,
		},
		{
			name: "not-found",
			args: args{
				name:           "not-found" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
				PublicId:       func() *string { s := "1"; return &s }(),
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantRowsUpdate:  0,
			wantErrMsg:      "record not found, search issue: error #1100",
			wantIsError:     errors.RecordNotFound,
			wantHostSources: true,
		},
		{
			name: "null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			newName:         "null-name" + id,
			wantErr:         true,
			wantRowsUpdate:  0,
			wantErrMsg:      "db.DoTx: target.(Repository).UpdateTarget: db.Update: name must not be empty: not null constraint violated: integrity violation: error #1001",
			wantHostSources: true,
		},
		{
			name: "null-description",
			args: args{
				name:           "null-description",
				fieldMaskPaths: []string{"Description"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			newTargetOpts:   []target.Option{target.WithDescription("null-description" + id)},
			wantErr:         false,
			wantRowsUpdate:  1,
			wantHostSources: true,
		},
		{
			name: "empty-field-mask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantRowsUpdate:  0,
			wantErrMsg:      "target.(Repository).UpdateTarget: empty field mask: parameter violation: error #104",
			wantIsError:     errors.EmptyFieldMask,
			wantHostSources: true,
		},
		{
			name: "nil-fieldmask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: nil,
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantRowsUpdate:  0,
			wantErrMsg:      "target.(Repository).UpdateTarget: empty field mask: parameter violation: error #104",
			wantIsError:     errors.EmptyFieldMask,
			wantHostSources: true,
		},
		{
			name: "read-only-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"CreateTime"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantRowsUpdate:  0,
			wantErrMsg:      "target.(Repository).UpdateTarget: invalid field mask: CreateTime: parameter violation: error #103",
			wantIsError:     errors.InvalidFieldMask,
			wantHostSources: true,
		},
		{
			name: "unknown-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Alice"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantRowsUpdate:  0,
			wantErrMsg:      "target.(Repository).UpdateTarget: invalid field mask: Alice: parameter violation: error #103",
			wantIsError:     errors.InvalidFieldMask,
			wantHostSources: true,
		},
		{
			name: "no-public-id",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
				PublicId:       pubId(""),
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantErrMsg:      "target.(Repository).UpdateTarget: missing target public id: parameter violation: error #100",
			wantIsError:     errors.InvalidParameter,
			wantRowsUpdate:  0,
			wantHostSources: true,
		},
		{
			name: "project-id-no-mask",
			args: args{
				name:      "project-id" + id,
				ProjectId: proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantErrMsg:      "target.(Repository).UpdateTarget: empty field mask: parameter violation: error #104",
			wantIsError:     errors.EmptyFieldMask,
			wantHostSources: true,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
			},
			newProjectId:    proj.PublicId,
			wantErr:         true,
			wantDup:         true,
			wantErrMsg:      " already exists in project " + proj.PublicId,
			wantIsError:     errors.NotUnique,
			wantHostSources: true,
		},
	}
	css := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), len(tests))
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := css[i]
			require, assert := require.New(t), assert.New(t)
			ctx := context.Background()
			if tt.wantDup {
				_ = tcp.TestTarget(ctx, t, conn, proj.PublicId, tt.args.name)
			}

			testHostSetIds := []string{}
			if tt.wantHostSources {
				testCats := static.TestCatalogs(t, conn, proj.PublicId, 1)
				hsets := static.TestSets(t, conn, testCats[0].GetPublicId(), 5)
				testHostSetIds = make([]string, 0, len(hsets))
				for _, hs := range hsets {
					testHostSetIds = append(testHostSetIds, hs.PublicId)
				}
				tt.newTargetOpts = append(
					tt.newTargetOpts,
					target.WithHostSources(testHostSetIds),
				)
			}

			cls := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, 5)
			var testClIds []string
			var testCredLibs []*target.CredentialLibrary
			for _, cl := range cls {
				testCredLibs = append(testCredLibs, &target.CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						CredentialLibraryId: cl.PublicId,
						CredentialPurpose:   string(credential.BrokeredPurpose),
					},
				})
				testClIds = append(testClIds, cl.PublicId)
			}

			tt.newTargetOpts = append(
				tt.newTargetOpts,
				target.WithCredentialLibraries(testCredLibs),
			)
			name := tt.newName
			if name == "" {
				name = tcp.TestId(t)
			}
			tar := tcp.TestTarget(ctx, t, conn, tt.newProjectId, name, tt.newTargetOpts...)
			updateTarget := tcp.NewTestTarget(
				ctx,
				tt.args.ProjectId,
				target.WithName(tt.args.name),
				target.WithDescription(tt.args.description),
				target.WithDefaultPort(tt.args.port),
				target.WithAddress(tt.args.address),
			)
			updateTarget.SetPublicId(ctx, tar.GetPublicId())
			if tt.args.PublicId != nil {
				ut := updateTarget.(*tcp.Target)
				ut.PublicId = *tt.args.PublicId
			}

			targetAfterUpdate, updatedRows, err := repo.UpdateTarget(ctx, updateTarget, tar.GetVersion(), tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				assert.Nil(targetAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.NotEmpty(err.Error())
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tar.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			require.NotNil(targetAfterUpdate)
			assert.Equal(tt.wantRowsUpdate, updatedRows)

			hostSources := targetAfterUpdate.GetHostSources()
			credSources := targetAfterUpdate.GetCredentialSources()
			afterUpdateIds := make([]string, 0, len(hostSources))
			for _, hs := range hostSources {
				afterUpdateIds = append(afterUpdateIds, hs.Id())
			}
			assert.Equal(testHostSetIds, afterUpdateIds)
			if len(tt.wantAddress) != 0 {
				assert.Equal(tt.wantAddress, targetAfterUpdate.GetAddress())
			} else {
				assert.Equal(tt.args.address, targetAfterUpdate.GetAddress())
			}

			afterUpdateIds = make([]string, 0, len(credSources))
			for _, cl := range credSources {
				afterUpdateIds = append(afterUpdateIds, cl.Id())
			}
			assert.ElementsMatch(testClIds, afterUpdateIds)

			switch tt.name {
			case "valid-no-op":
				assert.Equal(tar.GetUpdateTime().String(), targetAfterUpdate.GetUpdateTime().String())
			default:
				assert.NotEqual(tar.GetUpdateTime(), targetAfterUpdate.GetUpdateTime())
			}
			foundTarget, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
			assert.NoError(err)
			assert.True(proto.Equal(targetAfterUpdate.((*tcp.Target)), foundTarget.((*tcp.Target))))
			assert.Equal(targetAfterUpdate.GetAddress(), foundTarget.GetAddress())
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.args.description == "" {
				assert.Equal(foundTarget.GetDescription(), "")
				dbassert.IsNull(foundTarget, "description")
			}
			err = db.TestVerifyOplog(t, rw, tar.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
