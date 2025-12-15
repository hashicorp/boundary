// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHostSetMember_InsertDelete tests insertion and validates the lookup via set IDs
// function as well. After, we remove set memberships one at a time and validate
// the cleanup function removes the hosts.
func TestHostSetMember_InsertDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	plg := plugin.TestPlugin(t, conn, "create")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	}

	repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
	require.NoError(t, err)

	cats := TestCatalogs(t, conn, prj.PublicId, plg.PublicId, 2)

	blueCat := cats[0]
	blueSet1 := TestSet(t, conn, kms, sched, blueCat, plgm)
	blueSet2 := TestSet(t, conn, kms, sched, blueCat, plgm)
	blueSet3 := TestSet(t, conn, kms, sched, blueCat, plgm)

	hostId, err := db.NewPublicId(ctx, globals.PluginHostPrefix)
	require.NoError(t, err)
	blueHost1 := NewHost(ctx, blueCat.PublicId, "blue1", withPluginId(plg.GetPublicId()))
	blueHost1.PublicId = hostId
	require.NoError(t, rw.Create(ctx, blueHost1))

	hostId, err = db.NewPublicId(ctx, globals.PluginHostPrefix)
	require.NoError(t, err)
	blueHost2 := NewHost(ctx, blueCat.PublicId, "blue2", withPluginId(plg.GetPublicId()))
	blueHost2.PublicId = hostId
	require.NoError(t, rw.Create(ctx, blueHost2))

	hostId, err = db.NewPublicId(ctx, globals.PluginHostPrefix)
	require.NoError(t, err)
	blueHost3 := NewHost(ctx, blueCat.PublicId, "blue3", withPluginId(plg.GetPublicId()))
	blueHost3.PublicId = hostId
	require.NoError(t, rw.Create(ctx, blueHost3))

	hostId, err = db.NewPublicId(ctx, globals.PluginHostPrefix)
	require.NoError(t, err)
	blueHost4 := NewHost(ctx, blueCat.PublicId, "blue4", withPluginId(plg.GetPublicId()))
	blueHost4.PublicId = hostId
	require.NoError(t, rw.Create(ctx, blueHost4))

	greenCat := cats[1]
	greenSet := TestSet(t, conn, kms, sched, greenCat, plgm)

	tests := []struct {
		name    string
		set     string
		hosts   []*Host
		wantErr bool
		direct  bool
	}{
		{
			name:  "valid-host-in-set",
			set:   blueSet1.PublicId,
			hosts: []*Host{blueHost1},
		},
		{
			name:  "valid-other-host-in-set",
			set:   blueSet2.PublicId,
			hosts: []*Host{blueHost2},
		},
		{
			name:  "valid-two-hosts-in-set",
			set:   blueSet3.PublicId,
			hosts: []*Host{blueHost3, blueHost4},
		},
		{
			name:    "invalid-diff-catalogs",
			set:     greenSet.PublicId,
			hosts:   []*Host{blueHost1},
			wantErr: true,
		},
		{
			name:    "test-vet-for-write-no-set",
			hosts:   []*Host{blueHost1},
			wantErr: true,
			direct:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var hostIds []string
			for _, host := range tt.hosts {
				var got *HostSetMember
				var err error
				hostIds = append(hostIds, host.PublicId)
				if !tt.direct {
					got, err = NewHostSetMember(ctx, tt.set, host.PublicId)
				} else {
					got = &HostSetMember{
						HostSetMember: &store.HostSetMember{
							SetId: tt.set,
						},
					}
					if host != nil {
						got.HostId = host.PublicId
					}
				}
				require.NoError(err)
				require.NotNil(got)
				err2 := rw.Create(ctx, got)
				if tt.wantErr {
					assert.Error(err2)
					return
				}
				assert.NoError(err2)
			}

			// Run a test on the aggregate to validate looking up sets
			for _, host := range tt.hosts {
				agg := &hostAgg{PublicId: host.PublicId}
				require.NoError(rw.LookupByPublicId(ctx, agg))
				h := agg.toHost()
				assert.ElementsMatch(h.SetIds, []string{tt.set})
			}

			set, _, err := repo.LookupSet(ctx, tt.set)
			require.NoError(err)
			require.NotNil(set)
			require.ElementsMatch(set.HostIds, hostIds)
		})
	}

	hosts, err := repo.ListHostsBySetIds(ctx, []string{blueSet1.PublicId, blueSet2.PublicId})
	require.NoError(t, err)
	require.Len(t, hosts, 2)

	// Base case the count by catalog ID
	hosts, _, _, err = repo.listHosts(ctx, blueCat.PublicId)
	require.NoError(t, err)
	assert.Len(t, hosts, 4)

	j, err := newOrphanedHostCleanupJob(ctx, rw, rw, kms)
	require.NoError(t, err)
	// Delete first membership, validate host is gone
	got, err := NewHostSetMember(ctx, blueSet1.PublicId, blueHost1.PublicId)
	require.NoError(t, err)
	require.NotNil(t, got)
	num, err := rw.Delete(ctx, got)
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	count, err := j.deleteOrphanedHosts(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NoError(t, db.TestVerifyOplog(t, rw, blueHost1.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
	hosts, _, _, err = repo.listHosts(ctx, blueCat.PublicId)
	require.NoError(t, err)
	require.Len(t, hosts, 3)

	// Delete second, validate second host is gone
	got, err = NewHostSetMember(ctx, blueSet2.PublicId, blueHost2.PublicId)
	require.NoError(t, err)
	require.NotNil(t, got)
	num, err = rw.Delete(ctx, got)
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	count, err = j.deleteOrphanedHosts(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NoError(t, db.TestVerifyOplog(t, rw, blueHost2.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
	hosts, _, _, err = repo.listHosts(ctx, blueCat.PublicId)
	require.NoError(t, err)
	require.Len(t, hosts, 2)

	// Delete third set, validate remaining hosts are gone
	gotSet, err := NewHostSet(ctx, blueCat.PublicId)
	require.NoError(t, err)
	require.NotNil(t, got)
	gotSet.PublicId = blueSet3.PublicId
	num, err = rw.Delete(ctx, gotSet)
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	count, err = j.deleteOrphanedHosts(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.NoError(t, db.TestVerifyOplog(t, rw, blueHost3.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
	assert.NoError(t, db.TestVerifyOplog(t, rw, blueHost4.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
	hosts, _, _, err = repo.listHosts(ctx, blueCat.PublicId)
	require.NoError(t, err)
	require.Len(t, hosts, 0)
}

func TestHostSetMember_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin_set_member"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &HostSetMember{
				HostSetMember: &store.HostSetMember{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &HostSetMember{
				HostSetMember: &store.HostSetMember{},
				tableName:     tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
