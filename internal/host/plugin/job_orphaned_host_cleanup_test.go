// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOrphanedHostCleanupJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
	}
	tests := []struct {
		name        string
		args        args
		options     []Option
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "nil reader",
			args: args{
				w:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil writer",
			args: args{
				r:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil kms",
			args: args{
				r: rw,
				w: rw,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := newOrphanedHostCleanupJob(ctx, tt.args.r, tt.args.w, tt.args.kms)
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
		})
	}
}

func TestOrphanedHostCleanupJob_Run(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
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

	r, err := newOrphanedHostCleanupJob(ctx, rw, rw, kmsCache)
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
	host1 := TestHost(t, conn, cat.GetPublicId(), "host with membership")
	TestSetMembers(t, conn, set1.GetPublicId(), []*Host{host1})

	// 1 host with no set membership
	TestHost(t, conn, cat.GetPublicId(), "host2")

	// Run sync again with the newly created set
	err = r.Run(context.Background())
	require.NoError(err)
	// The single existing set should have been processed
	assert.Equal(1, r.numHosts)
	assert.Equal(1, r.numProcessed)

	// 5 host with no set membership
	TestHost(t, conn, cat.GetPublicId(), "1")
	TestHost(t, conn, cat.GetPublicId(), "2")
	TestHost(t, conn, cat.GetPublicId(), "3")
	TestHost(t, conn, cat.GetPublicId(), "4")
	TestHost(t, conn, cat.GetPublicId(), "5")

	// Run sync again with the freshly synced set
	err = r.Run(context.Background())
	require.NoError(err)
	// The single existing set should have been processed
	assert.Equal(5, r.numHosts)
	assert.Equal(5, r.numProcessed)

	// Run sync again with the freshly synced set
	err = r.Run(context.Background())
	require.NoError(err)
	// The single existing set should have been processed
	assert.Equal(0, r.numHosts)
	assert.Equal(0, r.numProcessed)

	require.NoError(rw.LookupById(ctx, host1))
}
