// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreferredEndpoint_Create(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "create")
	catalog := hostplugin.TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	set := hostplugin.TestSet(t, conn, kmsCache, sched, catalog, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	})

	type args struct {
		hostSetId string
		priority  uint32
		condition string
	}
	tests := []struct {
		name            string
		args            args
		want            *host.PreferredEndpoint
		wantErr         bool
		wantIsErr       errors.Code
		create          bool
		wantCreateErr   bool
		wantCreateIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				hostSetId: set.PublicId,
				priority:  1,
				condition: "cidr:1.2.3.4",
			},
			create: true,
			want: func() *host.PreferredEndpoint {
				want := host.AllocPreferredEndpoint()
				want.HostSetId = set.PublicId
				want.Condition = "cidr:1.2.3.4"
				want.Priority = 1
				return want
			}(),
		},
		{
			name: "dup", // must follow "valid" test. Url must be be unique for an OidcMethodId
			args: args{
				hostSetId: set.PublicId,
				priority:  1,
				condition: "cidr:1.2.3.4",
			},
			create: true,
			want: func() *host.PreferredEndpoint {
				want := host.AllocPreferredEndpoint()
				want.HostSetId = set.PublicId
				want.Condition = "cidr:1.2.3.4"
				want.Priority = 1
				return want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "bad-condition",
			args: args{
				hostSetId: set.PublicId,
				priority:  1,
				condition: "foobar:1.2.3.4",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-host-set",
			args: args{
				hostSetId: "",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-priority",
			args: args{
				hostSetId: set.PublicId,
				priority:  0,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-condition",
			args: args{
				hostSetId: set.PublicId,
				priority:  1,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := host.NewPreferredEndpoint(ctx, tt.args.hostSetId, tt.args.priority, tt.args.condition)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				ctx := context.Background()
				err = rw.Create(ctx, got)
				if tt.wantCreateErr {
					assert.Error(err)
					assert.True(errors.Match(errors.T(tt.wantCreateIsErr), err))
					return
				} else {
					assert.NoError(err)
				}
				found := host.AllocPreferredEndpoint()
				require.NoError(rw.LookupWhere(ctx, found, "host_set_id = ? and priority = ?", []any{tt.args.hostSetId, tt.args.priority}))
				assert.Equal(got, found)
			}
		})
	}
}

func TestPreferredEndpoint_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "create")
	catalog := hostplugin.TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	set := hostplugin.TestSet(t, conn, kmsCache, sched, catalog, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	})

	peFunc := func(priority uint32, condition string) *host.PreferredEndpoint {
		ep, err := host.NewPreferredEndpoint(ctx, set.PublicId, priority, condition)
		require.NoError(t, err)
		return ep
	}

	tests := []struct {
		pes             []*host.PreferredEndpoint
		name            string
		overrides       func(*host.PreferredEndpoint)
		wantErr         bool
		wantRowsDeleted int
	}{
		{
			name:            "valid-single",
			pes:             []*host.PreferredEndpoint{peFunc(1, "cidr:1.2.3.4")},
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-host-set-id",
			pes:             []*host.PreferredEndpoint{peFunc(1, "cidr:1.2.3.4")},
			overrides:       func(pe *host.PreferredEndpoint) { pe.HostSetId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			var eput *host.PreferredEndpoint
			for _, pe := range tt.pes {
				cloned := pe.Clone()
				if eput == nil {
					eput = cloned
				}
				require.NoError(rw.Create(ctx, &cloned))
			}
			if tt.overrides != nil {
				tt.overrides(eput)
			}

			deletedRows, err := rw.Delete(ctx, &eput, db.WithWhere("host_set_id = ?", eput.HostSetId))
			if tt.wantErr {
				require.Error(err)
				return
			}

			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			require.Equal(tt.wantRowsDeleted, deletedRows)
			found := host.AllocPreferredEndpoint()
			err = rw.LookupWhere(ctx, &found, "host_set_id = ?", []any{set.PublicId})
			assert.True(errors.IsNotFoundError(err))
		})
	}
}
