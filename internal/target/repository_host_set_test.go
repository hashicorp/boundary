package target

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_AddTargetHostSets(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	staticOrg, staticProj := iam.TestScopes(t, iamRepo)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	createHostSetsFn := func(orgs, projects []string) []string {
		results := []string{}
		for _, publicId := range orgs {
			cats := static.TestCatalogs(t, conn, publicId, 1)
			hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 1)
			results = append(results, hsets[0].PublicId)
		}
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
		opt           []Option
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs error
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
			require.NoError(conn.Where("1=1").Delete(allocTargetHostSet()).Error)
			require.NoError(conn.Where("1=1").Delete(allocTcpTarget()).Error)

			projTarget := TestTcpTarget(t, conn, staticProj.PublicId, "static-proj")

			var hostSetIds []string
			origTarget, origHostSet, _, err := repo.LookupTarget(context.Background(), projTarget.PublicId)
			require.NoError(err)
			require.Equal(0, len(origHostSet))

			if tt.args.wantTargetIds {
				hostSetIds = createHostSetsFn([]string{staticOrg.PublicId}, []string{staticProj.PublicId})
			}

			gotTarget, gotHostSets, _, err := repo.AddTargetHostSets(context.Background(), projTarget.PublicId, tt.args.targetVersion, hostSetIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				// test to see of the target version update oplog was not created
				err = db.TestVerifyOplog(t, rw, projTarget.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
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
			gotHostSet := map[string]*TargetSet{}
			for _, s := range gotHostSets {
				gotHostSet[s.PublicId] = s
			}

			// TODO (jimlambrt 9/2020) - unfortunately, we can currently
			// test to make sure that the oplog entry for a target create
			// doesn't exist because the db.TestVerifyOplog doesn't really
			// support that level of testing and the previous call to
			// TestTcpTarget would create an oplog entry for the
			// create on the target.   Once TestVerifyOplog supports the
			// appropriate granularity, we should add an appropriate assert.

			// test to see of the target version update oplog was  created
			err = db.TestVerifyOplog(t, rw, projTarget.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundHostSets, err := fetchSets(context.Background(), rw, projTarget.PublicId)
			require.NoError(err)
			for _, s := range foundHostSets {
				assert.NotEmpty(gotHostSet[s.PublicId])
			}

			target, ths, _, err := repo.LookupTarget(context.Background(), projTarget.PublicId)
			require.NoError(err)
			assert.Equal(tt.args.targetVersion+1, target.GetVersion())
			assert.Equal(origTarget.GetVersion(), target.GetVersion()-1)
			assert.Equal(gotHostSets, ths)
			assert.True(proto.Equal(gotTarget.(*TcpTarget), target.(*TcpTarget)))
		})
	}
	t.Run("add-existing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		cats := static.TestCatalogs(t, conn, staticProj.PublicId, 1)
		hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 3)
		hs1 := hsets[0]
		hs2 := hsets[1]
		hs3 := hsets[2]

		projTarget := TestTcpTarget(t, conn, staticProj.PublicId, "add-existing")
		_, gotHostSets, _, err := repo.AddTargetHostSets(context.Background(), projTarget.PublicId, 1, []string{hs1.PublicId})
		require.NoError(err)
		assert.Len(gotHostSets, 1)
		assert.Equal(hs1.PublicId, gotHostSets[0].PublicId)

		// Adding hs1 again should error
		_, _, _, err = repo.AddTargetHostSets(context.Background(), projTarget.PublicId, 2, []string{hs1.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Adding multiple with hs1 in set should error
		_, _, _, err = repo.AddTargetHostSets(context.Background(), projTarget.PublicId, 2, []string{hs3.PublicId, hs2.PublicId, hs1.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Previous transactions should have been rolled back and only hs1 should be associated
		gotHostSets, err = fetchSets(context.Background(), rw, projTarget.PublicId)
		require.NoError(err)
		assert.Len(gotHostSets, 1)
		assert.Equal(hs1.PublicId, gotHostSets[0].PublicId)
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
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	type args struct {
		target                Target
		targetIdOverride      *string
		targetVersionOverride *uint32
		createCnt             int
		deleteCnt             int
		opt                   []Option
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
				target:    TestTcpTarget(t, conn, proj.PublicId, "valid"),
				createCnt: 5,
				deleteCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				target:    TestTcpTarget(t, conn, proj.PublicId, "valid-keeping-some"),
				createCnt: 5,
				deleteCnt: 2,
			},
			wantRowsDeleted: 2,
			wantErr:         false,
		},
		{
			name: "no-deletes",
			args: args{
				target:    TestTcpTarget(t, conn, proj.PublicId, "no-deletes"),
				createCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				target:           TestTcpTarget(t, conn, proj.PublicId, "not-found"),
				targetIdOverride: func() *string { id := testId(t); return &id }(),
				createCnt:        5,
				deleteCnt:        5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "missing-target-id",
			args: args{
				target:           TestTcpTarget(t, conn, proj.PublicId, "missing-target-id"),
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
				target:                TestTcpTarget(t, conn, proj.PublicId, "zero-version"),
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
				target:                TestTcpTarget(t, conn, proj.PublicId, "bad-version"),
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
			_, addedHostSets, _, err := repo.AddTargetHostSets(context.Background(), tt.args.target.GetPublicId(), 1, hsIds, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(addedHostSets))

			deleteHostSets := make([]string, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteHostSets = append(deleteHostSets, hsIds[i])
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
			deletedRows, err := repo.DeleteTargeHostSets(context.Background(), targetId, targetVersion, deleteHostSets, tt.args.opt...)
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

		projTarget := TestTcpTarget(t, conn, proj.PublicId, "delete-unassociated")
		_, gotHostSets, _, err := repo.AddTargetHostSets(context.Background(), projTarget.PublicId, 1, []string{hs1.PublicId, hs2.PublicId})
		require.NoError(err)
		assert.Len(gotHostSets, 2)
		assert.Equal(hs1.PublicId, gotHostSets[0].PublicId)

		// Deleting an unassociated host set should return an error
		delCount, err := repo.DeleteTargeHostSets(context.Background(), projTarget.PublicId, 2, []string{hs3.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Deleting host sets which includes an unassociated host set should return an error
		delCount, err = repo.DeleteTargeHostSets(context.Background(), projTarget.PublicId, 2, []string{hs1.PublicId, hs2.PublicId, hs3.PublicId})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Previous transactions should have been rolled back
		gotHostSets, err = fetchSets(context.Background(), rw, projTarget.PublicId)
		require.NoError(err)
		assert.Len(gotHostSets, 2)
	})
}

func TestRepository_SetTargetHostSets(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, testKms)
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

	setupFn := func(target Target) []*TargetSet {
		hs := createHostSetsFn()
		_, created, _, err := repo.AddTargetHostSets(context.Background(), target.GetPublicId(), 1, hs)
		require.NoError(t, err)
		require.Equal(t, 10, len(created))
		return created
	}
	type args struct {
		target            Target
		targetVersion     uint32
		hostSetIds        []string
		addToOrigHostSets bool
		opt               []Option
	}
	tests := []struct {
		name             string
		setup            func(Target) []*TargetSet
		args             args
		wantAffectedRows int
		wantErr          bool
	}{
		{
			name:  "clear",
			setup: setupFn,
			args: args{
				target:        TestTcpTarget(t, conn, proj.PublicId, "clear"),
				targetVersion: 2, // yep, since setupFn will increment it to 2
				hostSetIds:    []string{},
			},
			wantErr:          false,
			wantAffectedRows: 10,
		},
		{
			name:  "no-change",
			setup: setupFn,
			args: args{
				target:            TestTcpTarget(t, conn, proj.PublicId, "no-change"),
				targetVersion:     2, // yep, since setupFn will increment it to 2
				hostSetIds:        []string{},
				addToOrigHostSets: true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "add-sets",
			setup: setupFn,
			args: args{
				target:            TestTcpTarget(t, conn, proj.PublicId, "add-sets"),
				targetVersion:     2, // yep, since setupFn will increment it to 2
				hostSetIds:        []string{testHostSetIds[0], testHostSetIds[1]},
				addToOrigHostSets: true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "add host sets with zero version",
			setup: setupFn,
			args: args{
				target:            TestTcpTarget(t, conn, proj.PublicId, "add host sets with zero version"),
				targetVersion:     0,
				hostSetIds:        []string{testHostSetIds[0], testHostSetIds[1]},
				addToOrigHostSets: true,
			},
			wantErr: true,
		},
		{
			name:  "remove existing and add users and grps",
			setup: setupFn,
			args: args{
				target:            TestTcpTarget(t, conn, proj.PublicId, "remove existing and add host sets"),
				targetVersion:     2, // yep, since setupFn will increment it to 2
				hostSetIds:        []string{testHostSetIds[0], testHostSetIds[1]},
				addToOrigHostSets: false,
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var origHostSets []*TargetSet
			if tt.setup != nil {
				origHostSets = tt.setup(tt.args.target)
			}
			if tt.args.addToOrigHostSets {
				origIds := make([]string, 0, len(origHostSets))
				for _, s := range origHostSets {
					origIds = append(origIds, s.PublicId)
				}
				tt.args.hostSetIds = append(tt.args.hostSetIds, origIds...)
			}
			origTarget, lookedUpHs, _, err := repo.LookupTarget(context.Background(), tt.args.target.GetPublicId())
			require.NoError(err)
			assert.Equal(len(origHostSets), len(lookedUpHs))

			got, _, affectedRows, err := repo.SetTargetHostSets(context.Background(), tt.args.target.GetPublicId(), tt.args.targetVersion, tt.args.hostSetIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				t.Log(err)
				return
			}
			t.Log(err)
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)
			assert.Equal(len(tt.args.hostSetIds), len(got))

			var wantIds []string
			wantIds = append(wantIds, tt.args.hostSetIds...)
			sort.Strings(wantIds)

			var gotIds []string
			if len(got) > 0 {
				gotIds = make([]string, 0, len(got))
				for _, s := range got {
					gotIds = append(gotIds, s.PublicId)
				}
			}
			sort.Strings(gotIds)
			assert.Equal(wantIds, gotIds)

			foundTarget, _, _, err := repo.LookupTarget(context.Background(), tt.args.target.GetPublicId())
			require.NoError(err)
			if tt.name != "no-change" {
				assert.Equalf(tt.args.targetVersion+1, foundTarget.GetVersion(), "%s unexpected version: %d/%d", tt.name, tt.args.targetVersion+1, foundTarget.GetVersion())
				assert.Equalf(origTarget.GetVersion(), foundTarget.GetVersion()-1, "%s unexpected version: %d/%d", tt.name, origTarget.GetVersion(), foundTarget.GetVersion()-1)
			}
			t.Logf("target: %v and origVersion/newVersion: %d/%d", foundTarget.GetPublicId(), origTarget.GetVersion(), foundTarget.GetVersion())
		})
	}
}
