package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	assertpkg "github.com/stretchr/testify/assert"
	requirepkg "github.com/stretchr/testify/require"
)

func TestNewSetSyncJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	plg := hostplg.TestPlugin(t, conn, "lookup")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{}),
	}

	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		plgm map[string]plgpb.HostPluginServiceClient
	}
	tests := []struct {
		name        string
		args        args
		options     []Option
		wantLimit   int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "nil reader",
			args: args{
				w:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil writer",
			args: args{
				r:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil kms",
			args: args{
				r:    rw,
				w:    rw,
				plgm: plgm,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil plgm",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			args: args{
				r:    rw,
				w:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:    rw,
				w:    rw,
				kms:  kmsCache,
				plgm: plgm,
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assertpkg.New(t), requirepkg.New(t)

			got, err := newSetSyncJob(ctx, tt.args.r, tt.args.w, tt.args.kms, tt.args.plgm, tt.options...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.args.r, got.reader)
			assert.Equal(tt.args.w, got.writer)
			assert.Equal(tt.args.kms, got.kms)
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestSetSyncJob_Run(t *testing.T) {
	t.Parallel()
	assert, require := assertpkg.New(t), requirepkg.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)

	plgServer := &TestPluginServer{}
	plg := hostplg.TestPlugin(t, conn, "run")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(plgServer),
	}

	r, err := newSetSyncJob(ctx, rw, rw, kmsCache, plgm)
	require.NoError(err)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	err = sche.RegisterJob(context.Background(), r)
	require.NoError(err)

	err = r.Run(context.Background())
	require.NoError(err)
	// No sets should have been synced.
	assert.Equal(0, r.numProcessed)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	set1 := TestSet(t, conn, kmsCache, sched, cat, plgm)
	plgServer.ListHostsFn = func(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
		assert.Len(req.GetSets(), 1)
		assert.Equal(set1.GetPublicId(), req.GetSets()[0].GetId())
		return &plgpb.ListHostsResponse{
			Hosts: []*plgpb.ListHostsResponseHost{
				{
					ExternalId:  "first",
					IpAddresses: []string{"10.0.0.1"},
					SetIds:      []string{req.GetSets()[0].GetId()},
				},
			},
		}, nil
	}

	hsa := &hostSetAgg{PublicId: set1.GetPublicId()}
	require.NoError(rw.LookupByPublicId(ctx, hsa))
	assert.Less(hsa.LastSyncTime.AsTime().UnixNano(), hsa.CreateTime.AsTime().UnixNano())

	// Run sync again with the newly created set
	err = r.Run(context.Background())
	require.NoError(err)
	// The single existing set should have been processed
	assert.Equal(1, r.numSets)
	assert.Equal(1, r.numProcessed)

	require.NoError(rw.LookupByPublicId(ctx, hsa))
	assert.Greater(hsa.LastSyncTime.AsTime().UnixNano(), hsa.CreateTime.AsTime().UnixNano())
	assert.False(hsa.NeedSync)
	firstSyncTime := hsa.LastSyncTime

	// Run sync again with the freshly synced set
	err = r.Run(context.Background())
	require.NoError(err)
	// The single existing set should have been processed
	assert.Equal(0, r.numSets)
	assert.Equal(0, r.numProcessed)

	// Set needs update
	hs, err := hsa.toHostSet(ctx)
	require.NoError(err)
	hs.NeedSync = true
	count, err := rw.Update(ctx, hs, []string{"NeedSync"}, nil)
	require.NoError(err)
	assert.Equal(1, count)
	assert.True(hs.NeedSync)

	// Run sync again with the set needing update
	err = r.Run(context.Background())
	require.NoError(err)
	// The single existing set should have been processed
	assert.Equal(1, r.numSets)
	assert.Equal(1, r.numProcessed)

	require.NoError(rw.LookupByPublicId(ctx, hs))
	assert.Greater(hs.GetLastSyncTime().AsTime().UnixNano(), firstSyncTime.AsTime().UnixNano())
	assert.False(hs.GetNeedSync())

	// Now, run a battery of tests with values for SyncIntervalSeconds
	type setArgs struct {
		syncIntervalSeconds int32
		lastSyncTime        *timestamp.Timestamp
		needsSync           bool
	}
	tests := []struct {
		name       string
		setArgs    setArgs
		expectSync bool
	}{
		{
			name: "never-synced-before-needs-sync-false",
			setArgs: setArgs{
				lastSyncTime: timestamp.New(time.Unix(0, 0)),
				needsSync:    false,
			},
			expectSync: true,
		},
		{
			name: "never-synced-before-needs-sync-true",
			setArgs: setArgs{
				lastSyncTime: timestamp.New(time.Unix(0, 0)),
				needsSync:    true,
			},
			expectSync: true,
		},
		{
			name: "never-synced-before-sync-disabled",
			setArgs: setArgs{
				syncIntervalSeconds: -1,
				lastSyncTime:        timestamp.New(time.Unix(0, 0)),
				needsSync:           true,
			},
			expectSync: true,
		},
		{
			name: "synced-just-now",
			setArgs: setArgs{
				lastSyncTime: timestamp.Now(),
				needsSync:    false,
			},
			expectSync: false,
		},
		{
			name: "synced-just-now-need-sync",
			setArgs: setArgs{
				lastSyncTime: timestamp.Now(),
				needsSync:    true,
			},
			expectSync: true,
		},
		{
			name: "synced-just-now-need-sync-but-sync-disabled",
			setArgs: setArgs{
				syncIntervalSeconds: -1,
				lastSyncTime:        timestamp.Now(),
				needsSync:           true,
			},
			expectSync: true,
		},
		{
			name: "synced-30-seconds-ago-default-time",
			setArgs: setArgs{
				lastSyncTime: timestamp.New(time.Now().Add(-60 * time.Second)),
				needsSync:    false,
			},
			expectSync: false,
		},
		{
			name: "synced-30-seconds-ago-custom-time",
			setArgs: setArgs{
				syncIntervalSeconds: 5,
				lastSyncTime:        timestamp.New(time.Now().Add(-60 * time.Second)),
				needsSync:           false,
			},
			expectSync: true,
		},
		{
			name: "synced-30-seconds-ago-custom-larger-time",
			setArgs: setArgs{
				syncIntervalSeconds: 90,
				lastSyncTime:        timestamp.New(time.Now().Add(-60 * time.Second)),
				needsSync:           false,
			},
			expectSync: false,
		},
		{
			name: "synced-30-seconds-ago-custom-larger-time-need-sync",
			setArgs: setArgs{
				syncIntervalSeconds: 60,
				lastSyncTime:        timestamp.New(time.Now().Add(-60 * time.Second)),
				needsSync:           true,
			},
			expectSync: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assertpkg.New(t), requirepkg.New(t)

			// Update set
			hs.LastSyncTime = tt.setArgs.lastSyncTime
			hs.NeedSync = tt.setArgs.needsSync
			hs.SyncIntervalSeconds = tt.setArgs.syncIntervalSeconds
			fieldMaskPaths := []string{"LastSyncTime", "NeedSync"}
			var setToNullPaths []string
			if hs.SyncIntervalSeconds == 0 {
				setToNullPaths = []string{"SyncIntervalSeconds"}
			} else {
				fieldMaskPaths = append(fieldMaskPaths, "SyncIntervalSeconds")
			}
			count, err := rw.Update(ctx, hs, fieldMaskPaths, setToNullPaths)
			require.NoError(err)
			assert.Equal(1, count)

			// Run job
			err = r.Run(context.Background())
			require.NoError(err)

			// Validate results
			var expNum int
			if tt.expectSync {
				expNum = 1
			}
			assert.Equal(expNum, r.numSets)
			assert.Equal(expNum, r.numProcessed)
		})
	}
}

func TestSetSyncJob_NextRunIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "lookup")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{}),
	}
	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet := TestSet(t, conn, kmsCache, sched, catalog, plgm)

	type setArgs struct {
		syncIntervalSeconds int32
		lastSyncTime        *timestamp.Timestamp
		needsSync           bool
	}
	tests := []struct {
		name         string
		syncInterval time.Duration
		setArgs      setArgs
		want         time.Duration
	}{
		{
			name: "never-synced-before",
			setArgs: setArgs{
				lastSyncTime: timestamp.New(time.Unix(0, 0)),
				needsSync:    false,
			},
			want: 0,
		},
		{
			name: "synced-just-now",
			setArgs: setArgs{
				lastSyncTime: timestamp.Now(),
				needsSync:    false,
			},
			want: setSyncJobRunInterval,
		},
		{
			name: "synced-just-now-need-sync",
			setArgs: setArgs{
				lastSyncTime: timestamp.Now(),
				needsSync:    true,
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assertpkg.New(t), requirepkg.New(t)
			r, err := newSetSyncJob(ctx, rw, rw, kmsCache, plgm)
			assert.NoError(err)
			require.NotNil(r)

			hostSet.NeedSync = tt.setArgs.needsSync
			hostSet.LastSyncTime = tt.setArgs.lastSyncTime
			hostSet.SyncIntervalSeconds = tt.setArgs.syncIntervalSeconds
			fieldMaskPaths := []string{"LastSyncTime", "NeedSync"}
			var setToNullPaths []string
			if hostSet.SyncIntervalSeconds == 0 {
				setToNullPaths = []string{"SyncIntervalSeconds"}
			} else {
				fieldMaskPaths = append(fieldMaskPaths, "SyncIntervalSeconds")
			}
			_, err = rw.Update(ctx, hostSet, fieldMaskPaths, setToNullPaths)
			require.NoError(err)

			got, err := r.NextRunIn()
			require.NoError(err)
			// Round to five seconds to account for lost time between updating set and determining next run
			assert.Equal(tt.want.Round(5*time.Second), got.Round(5*time.Second))
		})
	}
}
