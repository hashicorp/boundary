// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	targetstore "github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func allocTargetHostSet() target.TargetHostSet {
	return target.TargetHostSet{
		TargetHostSet: &targetstore.TargetHostSet{},
	}
}

func TestRepository_AddTargetHostSets(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, staticProj := iam.TestScopes(t, iamRepo)
	repo, err := target.NewRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)

	createHostSetsFn := func(projects []string) []string {
		results := []string{}
		for _, publicId := range projects {
			cats := static.TestCatalogs(t, conn, publicId, 1)
			hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 1)
			results = append(results, hsets[0].PublicId)
		}
		return results
	}

	type args struct {
		targetVersion uint32
		wantTargetIds bool
		wantAddress   bool
		opt           []target.Option
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantErrMsg string
		wantErrIs  error
	}{
		{
			name: "valid",
			args: args{
				targetVersion: 1,
				wantTargetIds: true,
			},
			wantErr: false,
		},
		{
			name: "address-mutually-exclusive-relationship",
			args: args{
				targetVersion: 1,
				wantAddress:   true,
				wantTargetIds: true,
			},
			wantErr:    true,
			wantErrMsg: "unable to add host sources because a network address is directly assigned to the given target",
		},
		{
			name: "bad-version",
			args: args{
				targetVersion: 1000,
				wantTargetIds: true,
			},
			wantErr: true,
		},
		{
			name: "zero-version",
			args: args{
				targetVersion: 0,
				wantTargetIds: true,
			},
			wantErr: true,
		},
		{
			name: "no-host-sets",
			args: args{
				targetVersion: 1,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			db.TestDeleteWhere(t, conn, func() any { i := allocTargetHostSet(); return &i }(), "1 = 1")
			db.TestDeleteWhere(t, conn, tcp.NewTestTarget(ctx, ""), "1 = 1")

			projTarget := tcp.TestTarget(ctx, t, conn, staticProj.PublicId, "static-proj")

			var address *target.Address
			if tt.args.wantAddress {
				address = target.TestTargetAddress(t, conn, projTarget.GetPublicId(), "8.8.8.8")
			}

			var hostSourceIds []string
			origTarget, err := repo.LookupTarget(ctx, projTarget.GetPublicId())
			require.NoError(err)
			require.Equal(0, len(origTarget.GetHostSources()))

			if address != nil {
				require.Equal(address.GetAddress(), origTarget.GetAddress())
			}

			if tt.args.wantTargetIds {
				hostSourceIds = createHostSetsFn([]string{staticProj.PublicId})
			}

			gotTarget, err := repo.AddTargetHostSources(ctx, projTarget.GetPublicId(), tt.args.targetVersion, hostSourceIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				if tt.wantErrMsg != "" {
					assert.Contains(err.Error(), tt.wantErrMsg)
				}
				// test to see of the target version update oplog was not created
				err = db.TestVerifyOplog(t, rw, projTarget.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)

				// TODO (jimlambrt 9/2020) - unfortunately, we can currently
				// test to make sure that the oplog entry for a target create
				// doesn't exist because the db.TestVerifyOplog doesn't really
				// support that level of testing and the previous call to
				// TestTcpTarget would create an oplog entry for the
				// create on the target.   Once TestVerifyOplog supports the
				// appropriate granularity, we should add an appropriate assert.

				return
			}
			require.NoError(err)

			gotHostSources := gotTarget.GetHostSources()
			gotHostSet := map[string]target.HostSource{}
			for _, s := range gotHostSources {
				gotHostSet[s.Id()] = s
			}

			// TODO (jimlambrt 9/2020) - unfortunately, we can currently
			// test to make sure that the oplog entry for a target create
			// doesn't exist because the db.TestVerifyOplog doesn't really
			// support that level of testing and the previous call to
			// TestTcpTarget would create an oplog entry for the
			// create on the target.   Once TestVerifyOplog supports the
			// appropriate granularity, we should add an appropriate assert.

			// test to see of the target version update oplog was  created
			err = db.TestVerifyOplog(t, rw, projTarget.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			tar, err := repo.LookupTarget(ctx, projTarget.GetPublicId())
			require.NoError(err)
			ths := tar.GetHostSources()
			assert.Equal(tt.args.targetVersion+1, tar.GetVersion())
			assert.Equal(origTarget.GetVersion(), tar.GetVersion()-1)
			assert.Equal(gotHostSources, ths)
			assert.True(proto.Equal(gotTarget.(*tcp.Target), tar.(*tcp.Target)))
			for _, s := range ths {
				assert.NotEmpty(gotHostSet[s.Id()])
			}
		})
	}
	t.Run("add-existing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		cats := static.TestCatalogs(t, conn, staticProj.PublicId, 1)
		hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 3)
		hs1 := hsets[0]
		hs2 := hsets[1]
		hs3 := hsets[2]

		ctx := context.Background()
		projTarget := tcp.TestTarget(ctx, t, conn, staticProj.PublicId, "add-existing")
		gotTarget, err := repo.AddTargetHostSources(ctx, projTarget.GetPublicId(), 1, []string{hs1.PublicId})
		require.NoError(err)
		gotHostSources := gotTarget.GetHostSources()
		assert.Len(gotHostSources, 1)
		assert.Equal(hs1.PublicId, gotHostSources[0].Id())

		// Adding hs1 again should error
		_, err = repo.AddTargetHostSources(ctx, projTarget.GetPublicId(), 2, []string{hs1.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Adding multiple with hs1 in set should error
		_, err = repo.AddTargetHostSources(ctx, projTarget.GetPublicId(), 2, []string{hs3.PublicId, hs2.PublicId, hs1.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Previous transactions should have been rolled back and only hs1 should be associated
		gotTarget, err = repo.LookupTarget(ctx, projTarget.GetPublicId())
		require.NoError(err)
		gotHostSources = gotTarget.GetHostSources()
		assert.Len(gotHostSources, 1)
		assert.Equal(hs1.PublicId, gotHostSources[0].Id())
	})
}

func TestRepository_DeleteTargetHosts(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	type args struct {
		target                target.Target
		targetIdOverride      *string
		targetVersionOverride *uint32
		createCnt             int
		deleteCnt             int
		opt                   []target.Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsErr       errors.Code
	}{
		{
			name: "valid",
			args: args{
				target:    tcp.TestTarget(ctx, t, conn, proj.PublicId, "valid"),
				createCnt: 5,
				deleteCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				target:    tcp.TestTarget(ctx, t, conn, proj.PublicId, "valid-keeping-some"),
				createCnt: 5,
				deleteCnt: 2,
			},
			wantRowsDeleted: 2,
			wantErr:         false,
		},
		{
			name: "no-deletes",
			args: args{
				target:    tcp.TestTarget(ctx, t, conn, proj.PublicId, "no-deletes"),
				createCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				target:           tcp.TestTarget(ctx, t, conn, proj.PublicId, "not-found"),
				targetIdOverride: func() *string { id := tcp.TestId(t); return &id }(),
				createCnt:        5,
				deleteCnt:        5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "missing-target-id",
			args: args{
				target:           tcp.TestTarget(ctx, t, conn, proj.PublicId, "missing-target-id"),
				targetIdOverride: func() *string { id := ""; return &id }(),
				createCnt:        5,
				deleteCnt:        5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				target:                tcp.TestTarget(ctx, t, conn, proj.PublicId, "zero-version"),
				targetVersionOverride: func() *uint32 { v := uint32(0); return &v }(),
				createCnt:             5,
				deleteCnt:             5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "bad-version",
			args: args{
				target:                tcp.TestTarget(ctx, t, conn, proj.PublicId, "bad-version"),
				targetVersionOverride: func() *uint32 { v := uint32(1000); return &v }(),
				createCnt:             5,
				deleteCnt:             5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			hsIds := make([]string, 0, tt.args.createCnt)
			if tt.args.createCnt > 0 {
				for i := 0; i < tt.args.createCnt; i++ {
					cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
					hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 1)
					hsIds = append(hsIds, hsets[0].PublicId)
				}
			}
			addedTarget, err := repo.AddTargetHostSources(context.Background(), tt.args.target.GetPublicId(), 1, hsIds, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(addedTarget.GetHostSources()))

			deleteHostSources := make([]string, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteHostSources = append(deleteHostSources, hsIds[i])
			}
			var targetId string
			switch {
			case tt.args.targetIdOverride != nil:
				targetId = *tt.args.targetIdOverride
			default:
				targetId = tt.args.target.GetPublicId()
			}
			var targetVersion uint32
			switch {
			case tt.args.targetVersionOverride != nil:
				targetVersion = *tt.args.targetVersionOverride
			default:
				targetVersion = 2
			}
			deletedRows, err := repo.DeleteTargetHostSources(context.Background(), targetId, targetVersion, deleteHostSources, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "unexpected error %s", err.Error())
				// TODO (jimlambrt 9/2020) - unfortunately, we can currently
				// test to make sure that the oplog entry for a target update
				// doesn't exist because the db.TestVerifyOplog doesn't really
				// support that level of testing and the previous call to
				// repo.AddTargetHostSets() would create an oplog entry for the
				// update to the target.   Once TestVerifyOplog supports the
				// appropriate granularity, we should add an appropriate assert.

				err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			// TODO (jimlambrt 9/2020) - unfortunately, we can currently
			// test to make sure that the oplog entry for a target update
			// doesn't exist because the db.TestVerifyOplog doesn't really
			// support that level of testing and the previous call to
			// repo.AddTargetHostSets() would create an oplog entry for the
			// update to the target.   Once TestVerifyOplog supports the
			// appropriate granularity,, we should add an appropriate assert.

			// we should find the oplog for the delete of target host sets
			err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
	t.Run("delete-unassociated", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
		hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 3)
		hs1 := hsets[0]
		hs2 := hsets[1]
		hs3 := hsets[2]

		ctx := context.Background()
		projTarget := tcp.TestTarget(ctx, t, conn, proj.PublicId, "delete-unassociated")
		gotTarget, err := repo.AddTargetHostSources(ctx, projTarget.GetPublicId(), 1, []string{hs1.PublicId, hs2.PublicId})
		require.NoError(err)
		gotHostSources := gotTarget.GetHostSources()
		assert.Len(gotHostSources, 2)
		assert.Equal(hs1.PublicId, gotHostSources[0].Id())

		// Deleting an unassociated host set should return an error
		delCount, err := repo.DeleteTargetHostSources(ctx, projTarget.GetPublicId(), 2, []string{hs3.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Deleting host sets which includes an unassociated host set should return an error
		delCount, err = repo.DeleteTargetHostSources(ctx, projTarget.GetPublicId(), 2, []string{hs1.PublicId, hs2.PublicId, hs3.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Previous transactions should have been rolled back
		gotTarget, err = repo.LookupTarget(ctx, projTarget.GetPublicId())
		require.NoError(err)
		gotHostSources = gotTarget.GetHostSources()
		assert.Len(gotHostSources, 2)
	})
}

func TestRepository_SetTargetHostSets(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)

	ctx := context.Background()
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	testCats := static.TestCatalogs(t, conn, proj.PublicId, 1)
	hsets := static.TestSets(t, conn, testCats[0].GetPublicId(), 5)
	testHostSetIds := make([]string, 0, len(hsets))
	for _, hs := range hsets {
		testHostSetIds = append(testHostSetIds, hs.PublicId)
	}

	createHostSetsFn := func() []string {
		results := []string{}
		for i := 0; i < 10; i++ {
			cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
			hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 1)
			results = append(results, hsets[0].PublicId)
		}
		return results
	}

	setupFn := func(target target.Target) []target.HostSource {
		hs := createHostSetsFn()
		addedTarget, err := repo.AddTargetHostSources(context.Background(), target.GetPublicId(), 1, hs)
		require.NoError(t, err)
		created := addedTarget.GetHostSources()
		require.Equal(t, 10, len(created))
		return created
	}
	type args struct {
		target               target.Target
		targetVersion        uint32
		hostSourceIds        []string
		addToOrigHostSources bool
		opt                  []target.Option
	}
	tests := []struct {
		name             string
		setup            func(target.Target) []target.HostSource
		args             args
		wantAffectedRows int
		wantErrMsg       string
		wantErr          bool
	}{
		{
			name:  "clear",
			setup: setupFn,
			args: args{
				target:        tcp.TestTarget(ctx, t, conn, proj.PublicId, "clear"),
				targetVersion: 2, // yep, since setupFn will increment it to 2
				hostSourceIds: []string{},
			},
			wantErr:          false,
			wantAffectedRows: 10,
		},
		{
			name: "address-mutually-exclusive-relationship",
			args: args{
				target:               tcp.TestTarget(ctx, t, conn, proj.PublicId, "invalid-host-source", target.WithAddress("8.8.8.8")),
				targetVersion:        2, // yep, since setupFn will increment it to 2
				hostSourceIds:        []string{testHostSetIds[0], testHostSetIds[1]},
				addToOrigHostSources: true,
			},
			wantErr:    true,
			wantErrMsg: "unable to set host sources because a network address is directly assigned to the given target",
		},
		{
			name:  "no-change",
			setup: setupFn,
			args: args{
				target:               tcp.TestTarget(ctx, t, conn, proj.PublicId, "no-change"),
				targetVersion:        2, // yep, since setupFn will increment it to 2
				hostSourceIds:        []string{},
				addToOrigHostSources: true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "add-sets",
			setup: setupFn,
			args: args{
				target:               tcp.TestTarget(ctx, t, conn, proj.PublicId, "add-sets"),
				targetVersion:        2, // yep, since setupFn will increment it to 2
				hostSourceIds:        []string{testHostSetIds[0], testHostSetIds[1]},
				addToOrigHostSources: true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "add host sets with zero version",
			setup: setupFn,
			args: args{
				target:               tcp.TestTarget(ctx, t, conn, proj.PublicId, "add host sets with zero version"),
				targetVersion:        0,
				hostSourceIds:        []string{testHostSetIds[0], testHostSetIds[1]},
				addToOrigHostSources: true,
			},
			wantErr: true,
		},
		{
			name:  "remove existing and add users and grps",
			setup: setupFn,
			args: args{
				target:               tcp.TestTarget(ctx, t, conn, proj.PublicId, "remove existing and add host sets"),
				targetVersion:        2, // yep, since setupFn will increment it to 2
				hostSourceIds:        []string{testHostSetIds[0], testHostSetIds[1]},
				addToOrigHostSources: false,
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var origHostSources []target.HostSource
			if tt.setup != nil {
				origHostSources = tt.setup(tt.args.target)
			}
			if tt.args.addToOrigHostSources {
				origIds := make([]string, 0, len(origHostSources))
				for _, s := range origHostSources {
					origIds = append(origIds, s.Id())
				}
				tt.args.hostSourceIds = append(tt.args.hostSourceIds, origIds...)
			}
			origTarget, err := repo.LookupTarget(context.Background(), tt.args.target.GetPublicId())
			require.NoError(err)
			assert.Equal(len(origHostSources), len(origTarget.GetHostSources()))

			got, _, affectedRows, err := repo.SetTargetHostSources(context.Background(), tt.args.target.GetPublicId(), tt.args.targetVersion, tt.args.hostSourceIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				t.Log(err)
				return
			}
			t.Log(err)
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)
			assert.Equal(len(tt.args.hostSourceIds), len(got))

			var wantIds []string
			wantIds = append(wantIds, tt.args.hostSourceIds...)
			sort.Strings(wantIds)

			var gotIds []string
			if len(got) > 0 {
				gotIds = make([]string, 0, len(got))
				for _, s := range got {
					gotIds = append(gotIds, s.Id())
				}
			}
			sort.Strings(gotIds)
			assert.Equal(wantIds, gotIds)

			foundTarget, err := repo.LookupTarget(context.Background(), tt.args.target.GetPublicId())
			require.NoError(err)
			if tt.name != "no-change" {
				assert.Equalf(tt.args.targetVersion+1, foundTarget.GetVersion(), "%s unexpected version: %d/%d", tt.name, tt.args.targetVersion+1, foundTarget.GetVersion())
				assert.Equalf(origTarget.GetVersion(), foundTarget.GetVersion()-1, "%s unexpected version: %d/%d", tt.name, origTarget.GetVersion(), foundTarget.GetVersion()-1)
			}
			t.Logf("target: %v and origVersion/newVersion: %d/%d", foundTarget.GetPublicId(), origTarget.GetVersion(), foundTarget.GetVersion())
		})
	}
}
