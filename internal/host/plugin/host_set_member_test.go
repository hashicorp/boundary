package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
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
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	plg := hostplg.TestPlugin(t, conn, "create")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	}

	cats := TestCatalogs(t, conn, prj.PublicId, plg.PublicId, 2)

	blueCat := cats[0]
	blueSet1 := TestSet(t, conn, kms, blueCat, plgm)
	blueSet2 := TestSet(t, conn, kms, blueCat, plgm)

	hostId, err := db.NewPublicId(HostPrefix)
	require.NoError(t, err)
	blueHost1 := NewHost(ctx, blueCat.PublicId, "abcd", withPluginId(plg.GetPublicId()))
	blueHost1.PublicId = hostId
	require.NoError(t, rw.Create(ctx, blueHost1))

	hostId, err = db.NewPublicId(HostPrefix)
	require.NoError(t, err)
	blueHost2 := NewHost(ctx, blueCat.PublicId, "zyxw", withPluginId(plg.GetPublicId()))
	blueHost2.PublicId = hostId
	require.NoError(t, rw.Create(ctx, blueHost2))

	greenCat := cats[1]
	greenSet := TestSet(t, conn, kms, greenCat, plgm)

	tests := []struct {
		name    string
		sets    []string
		host    *Host
		wantErr bool
		direct  bool
	}{
		{
			name: "valid-host-in-set",
			sets: []string{blueSet1.PublicId},
			host: blueHost1,
		},
		{
			name: "valid-other-host-in-set",
			sets: []string{blueSet2.PublicId},
			host: blueHost2,
		},
		{
			name:    "invalid-diff-catalogs",
			sets:    []string{greenSet.PublicId},
			host:    blueHost1,
			wantErr: true,
		},
		{
			name:    "test-vet-for-write-no-set",
			host:    blueHost1,
			sets:    []string{""},
			wantErr: true,
			direct:  true,
		},
		{
			name:    "test-vet-for-write-no-host",
			sets:    []string{blueSet1.PublicId},
			wantErr: true,
			direct:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			for _, set := range tt.sets {
				var got *HostSetMember
				var err error
				if !tt.direct {
					got, err = NewHostSetMember(ctx, set, tt.host.PublicId)
				} else {
					got = &HostSetMember{
						HostSetMember: &store.HostSetMember{
							SetId: set,
						},
					}
					if tt.host != nil {
						got.HostId = tt.host.PublicId
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
			agg := &hostAgg{PublicId: tt.host.PublicId}
			require.NoError(rw.LookupByPublicId(ctx, agg))
			h, err := agg.toHost(ctx)
			require.NoError(err)
			assert.ElementsMatch(h.SetIds, tt.sets)
		})
	}
	repo, err := NewRepository(rw, rw, kms, plgm)
	require.NoError(t, err)
	hosts, err := repo.ListHostsBySetIds(ctx, []string{blueSet1.PublicId, blueSet2.PublicId})
	require.NoError(t, err)
	require.Len(t, hosts, 2)

	// Base case the count by catalog ID
	hosts, err = repo.ListHostsByCatalogId(ctx, blueCat.PublicId)
	require.NoError(t, err)
	assert.Len(t, hosts, 2)

	// Delete first membership, validate host is gone
	got, err := NewHostSetMember(ctx, blueSet1.PublicId, blueHost1.PublicId)
	require.NoError(t, err)
	require.NotNil(t, got)
	num, err := rw.Delete(ctx, got)
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	require.NoError(t, repo.DeleteOrphanedHosts(ctx))
	hosts, err = repo.ListHostsByCatalogId(ctx, blueCat.PublicId)
	require.NoError(t, err)
	require.Len(t, hosts, 1)

	// Delete second, validate second host is gone
	got, err = NewHostSetMember(ctx, blueSet2.PublicId, blueHost2.PublicId)
	require.NoError(t, err)
	require.NotNil(t, got)
	num, err = rw.Delete(ctx, got)
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	require.NoError(t, repo.DeleteOrphanedHosts(ctx))
	hosts, err = repo.ListHostsByCatalogId(ctx, blueCat.PublicId)
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
