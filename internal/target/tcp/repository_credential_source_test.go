package tcp_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_AddTargetCredentialSources(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, staticProj := iam.TestScopes(t, iamRepo)
	repo, err := target.NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	cs := vault.TestCredentialStores(t, conn, wrapper, staticProj.GetPublicId(), 1)[0]
	libs := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 3)
	require.Len(t, libs, 3)
	lib1 := libs[0]
	lib2 := libs[1]
	lib3 := libs[2]

	type args struct {
		targetVersion uint32
		credLibIds    []string
	}
	tests := []struct {
		name           string
		args           args
		wantCredLibIds []string
		wantErr        bool
		wantErrCode    errors.Code
	}{
		{
			name: "zero-version",
			args: args{
				targetVersion: 0,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "no-cred-sources",
			args: args{
				targetVersion: 1,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid-single-source",
			args: args{
				targetVersion: 1,
				credLibIds:    []string{lib1.PublicId},
			},
			wantCredLibIds: []string{lib1.PublicId},
			wantErr:        false,
		},
		{
			name: "valid-multiple-sources",
			args: args{
				targetVersion: 1,
				credLibIds:    []string{lib1.PublicId, lib2.PublicId, lib3.PublicId},
			},
			wantCredLibIds: []string{lib1.PublicId, lib2.PublicId, lib3.PublicId},
			wantErr:        false,
		},
		{
			name: "invalid-source-id",
			args: args{
				targetVersion: 1,
				credLibIds:    []string{lib1.PublicId, lib2.PublicId, lib3.PublicId, "invalid-source-id"},
			},
			wantErr:     true,
			wantErrCode: errors.NotSpecificIntegrity,
		},
		{
			name: "bad-version",
			args: args{
				targetVersion: 1000,
				credLibIds:    []string{lib1.PublicId},
			},
			wantErr:     true,
			wantErrCode: errors.VersionMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			projTarget := tcp.TestTarget(t, conn, staticProj.PublicId, tt.name)
			credLibs := make([]*target.CredentialLibrary, 0, len(tt.args.credLibIds))
			for _, clid := range tt.args.credLibIds {
				credLibs = append(credLibs, target.TestNewCredentialLibrary(projTarget.PublicId, clid, credential.ApplicationPurpose))
			}

			gotTarget, _, gotCredSources, err := repo.AddTargetCredentialSources(context.Background(), projTarget.PublicId, tt.args.targetVersion, credLibs)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			assert.Len(gotCredSources, len(tt.wantCredLibIds))
			gotCredSourcesMap := map[string]target.CredentialSource{}
			for _, s := range gotCredSources {
				gotCredSourcesMap[s.Id()] = s
			}
			for _, id := range tt.wantCredLibIds {
				assert.NotEmpty(gotCredSourcesMap[id])
			}

			// test to see of the target version update oplog was created
			err = db.TestVerifyOplog(t, rw, projTarget.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			tar, _, lookupCredSources, err := repo.LookupTarget(context.Background(), projTarget.PublicId)
			require.NoError(err)
			assert.Equal(tt.args.targetVersion+1, tar.GetVersion())
			assert.Equal(projTarget.GetVersion(), tar.GetVersion()-1)
			assert.True(proto.Equal(gotTarget.(*tcp.Target), tar.(*tcp.Target)))
			assert.Equal(gotCredSources, lookupCredSources)
			for _, s := range lookupCredSources {
				assert.NotEmpty(gotCredSourcesMap[s.Id()])
				assert.Equal(projTarget.PublicId, s.TargetId())
			}
		})
	}
	t.Run("add-existing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		projTarget := tcp.TestTarget(t, conn, staticProj.PublicId, "add-existing")
		cl1 := target.TestNewCredentialLibrary(projTarget.PublicId, lib1.PublicId, credential.ApplicationPurpose)
		cl2 := target.TestNewCredentialLibrary(projTarget.PublicId, lib2.PublicId, credential.ApplicationPurpose)
		cl3 := target.TestNewCredentialLibrary(projTarget.PublicId, lib3.PublicId, credential.ApplicationPurpose)

		_, _, gotCredSources, err := repo.AddTargetCredentialSources(context.Background(), projTarget.PublicId, 1, []*target.CredentialLibrary{cl1})
		require.NoError(err)
		assert.Len(gotCredSources, 1)
		assert.Equal(lib1.PublicId, gotCredSources[0].Id())

		// Adding lib1 again should error
		_, _, _, err = repo.AddTargetCredentialSources(context.Background(), projTarget.PublicId, 2, []*target.CredentialLibrary{cl1})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Adding multiple with lib1 in set should error
		_, _, _, err = repo.AddTargetCredentialSources(context.Background(), projTarget.PublicId, 2, []*target.CredentialLibrary{cl3, cl2, cl1})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Previous transactions should have been rolled back and only lib1 should be associated
		_, _, lookupCredSources, err := repo.LookupTarget(context.Background(), projTarget.PublicId)
		require.NoError(err)
		assert.Len(lookupCredSources, 1)
		assert.Equal(lib1.PublicId, lookupCredSources[0].Id())
	})
	t.Run("target-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		cl1 := target.TestNewCredentialLibrary("fake-target-id", lib1.PublicId, credential.ApplicationPurpose)
		_, _, _, err := repo.AddTargetCredentialSources(context.Background(), "fake-target-id", 1, []*target.CredentialLibrary{cl1})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "unexpected error %s", err.Error())
	})
}

func TestRepository_DeleteTargetCredentialSources(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	repo, err := target.NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	type args struct {
		targetIdOverride      *string
		targetVersionOverride *uint32
		createCnt             int
		deleteCnt             int
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrCode     errors.Code
	}{
		{
			name: "valid",
			args: args{
				createCnt: 5,
				deleteCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				createCnt: 5,
				deleteCnt: 2,
			},
			wantRowsDeleted: 2,
			wantErr:         false,
		},
		{
			name: "no-deletes",
			args: args{
				createCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				targetIdOverride: func() *string { id := tcp.TestId(t); return &id }(),
				createCnt:        5,
				deleteCnt:        5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.RecordNotFound,
		},
		{
			name: "missing-target-id",
			args: args{
				targetIdOverride: func() *string { id := ""; return &id }(),
				createCnt:        5,
				deleteCnt:        5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				targetVersionOverride: func() *uint32 { v := uint32(0); return &v }(),
				createCnt:             5,
				deleteCnt:             5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "bad-version",
			args: args{
				targetVersionOverride: func() *uint32 { v := uint32(1000); return &v }(),
				createCnt:             5,
				deleteCnt:             5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.VersionMismatch,
		},
	}
	css := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), len(tests))
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			cs := css[i]

			tar := tcp.TestTarget(t, conn, proj.PublicId, tt.name)

			cls := make([]*target.CredentialLibrary, 0, tt.args.createCnt)
			if tt.args.createCnt > 0 {
				credLibs := vault.TestCredentialLibraries(t, conn, wrapper, cs.PublicId, tt.args.createCnt)
				for _, cl := range credLibs {
					cls = append(cls, target.TestNewCredentialLibrary(tar.GetPublicId(), cl.PublicId, credential.ApplicationPurpose))
				}
			}
			_, _, addedCredSources, err := repo.AddTargetCredentialSources(context.Background(), tar.GetPublicId(), 1, cls)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(addedCredSources))

			deleteCredSources := make([]*target.CredentialLibrary, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteCredSources = append(deleteCredSources, cls[i])
			}
			var targetId string
			switch {
			case tt.args.targetIdOverride != nil:
				targetId = *tt.args.targetIdOverride
			default:
				targetId = tar.GetPublicId()
			}
			var targetVersion uint32
			switch {
			case tt.args.targetVersionOverride != nil:
				targetVersion = *tt.args.targetVersionOverride
			default:
				targetVersion = 2
			}
			deletedRows, err := repo.DeleteTargetCredentialSources(context.Background(), targetId, targetVersion, deleteCredSources)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			// we should find the oplog for the delete of target credential libraries
			err = db.TestVerifyOplog(t, rw, tar.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
	t.Run("delete-unassociated", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		_, proj := iam.TestScopes(t, iamRepo)
		cs := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
		libs := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 3)
		require.Len(libs, 3)
		lib1 := libs[0]
		lib2 := libs[1]
		lib3 := libs[2]

		projTarget := tcp.TestTarget(t, conn, proj.PublicId, "add-existing")
		cl1 := target.TestNewCredentialLibrary(projTarget.PublicId, lib1.PublicId, credential.ApplicationPurpose)
		cl2 := target.TestNewCredentialLibrary(projTarget.PublicId, lib2.PublicId, credential.ApplicationPurpose)
		cl3 := target.TestNewCredentialLibrary(projTarget.PublicId, lib3.PublicId, credential.ApplicationPurpose)

		_, _, gotCredSources, err := repo.AddTargetCredentialSources(context.Background(), projTarget.PublicId, 1, []*target.CredentialLibrary{cl1, cl2})
		require.NoError(err)
		assert.Len(gotCredSources, 2)

		// Deleting an unassociated source should return an error
		delCount, err := repo.DeleteTargetCredentialSources(context.Background(), projTarget.PublicId, 2, []*target.CredentialLibrary{cl3})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Deleting sources which includes an unassociated source should return an error
		delCount, err = repo.DeleteTargetCredentialSources(context.Background(), projTarget.PublicId, 2, []*target.CredentialLibrary{cl1, cl2, cl3})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Previous transactions should have been rolled back and only lib1 should be associated
		_, _, lookupCredSources, err := repo.LookupTarget(context.Background(), projTarget.PublicId)
		require.NoError(err)
		assert.Len(lookupCredSources, 2)
	})
}

func TestRepository_SetTargetCredentialSources(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := target.NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	cs := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	credLibs := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)
	lib1 := credLibs[0]
	lib2 := credLibs[1]

	setupFn := func(tar target.Target) ([]target.CredentialSource, []*target.CredentialLibrary) {
		credLibs := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 10)
		cls := make([]*target.CredentialLibrary, 0, len(credLibs))
		for _, cl := range credLibs {
			cls = append(cls, target.TestNewCredentialLibrary(tar.GetPublicId(), cl.PublicId, credential.ApplicationPurpose))
		}

		_, _, created, err := repo.AddTargetCredentialSources(context.Background(), tar.GetPublicId(), 1, cls)
		require.NoError(t, err)
		require.Equal(t, 10, len(created))
		return created, cls
	}
	type args struct {
		targetVersion uint32
		clIds         []string
		addToOrigLibs bool
	}
	tests := []struct {
		name             string
		setup            func(target.Target) ([]target.CredentialSource, []*target.CredentialLibrary)
		args             args
		wantAffectedRows int
		wantErr          bool
		wantErrCode      errors.Code
	}{
		{
			name:  "clear",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				clIds:         []string{},
			},
			wantErr:          false,
			wantAffectedRows: 10,
		},
		{
			name:  "no-change",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				clIds:         []string{},
				addToOrigLibs: true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "add-cred-sources",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				clIds:         []string{lib1.PublicId, lib2.PublicId},
				addToOrigLibs: true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "zero version",
			setup: setupFn,
			args: args{
				targetVersion: 0,
				clIds:         []string{lib1.PublicId, lib2.PublicId},
				addToOrigLibs: true,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:  "bad version",
			setup: setupFn,
			args: args{
				targetVersion: 1000,
				clIds:         []string{lib1.PublicId, lib2.PublicId},
				addToOrigLibs: true,
			},
			wantErr:     true,
			wantErrCode: errors.VersionMismatch,
		},
		{
			name:  "remove existing and add cred libs",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				clIds:         []string{lib1.PublicId, lib2.PublicId},
				addToOrigLibs: false,
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			tar := tcp.TestTarget(t, conn, proj.PublicId, tt.name)

			var origCredSources []target.CredentialSource
			var origCredLibraries []*target.CredentialLibrary
			if tt.setup != nil {
				origCredSources, origCredLibraries = tt.setup(tar)
			}

			cls := make([]*target.CredentialLibrary, 0, len(tt.args.clIds))
			for _, clid := range tt.args.clIds {
				cls = append(cls, target.TestNewCredentialLibrary(tar.GetPublicId(), clid, credential.ApplicationPurpose))
			}
			var wantIds []string
			wantIds = append(wantIds, tt.args.clIds...)
			if tt.args.addToOrigLibs {
				cls = append(cls, origCredLibraries...)
				for _, cl := range origCredLibraries {
					wantIds = append(wantIds, cl.CredentialLibraryId)
				}
			}

			origTarget, _, lookupCredSources, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
			require.NoError(err)
			assert.Equal(origCredSources, lookupCredSources)

			_, got, affectedRows, err := repo.SetTargetCredentialSources(context.Background(), tar.GetPublicId(), tt.args.targetVersion, cls)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, affectedRows)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			t.Log(err)
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)

			assert.Equal(len(wantIds), len(got))
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

			foundTarget, _, _, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
			require.NoError(err)
			if tt.name != "no-change" {
				assert.Equalf(tt.args.targetVersion+1, foundTarget.GetVersion(), "%s unexpected version: %d/%d", tt.name, tt.args.targetVersion+1, foundTarget.GetVersion())
				assert.Equalf(origTarget.GetVersion(), foundTarget.GetVersion()-1, "%s unexpected version: %d/%d", tt.name, origTarget.GetVersion(), foundTarget.GetVersion()-1)
			}
		})
	}
	t.Run("missing-target-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		cl1 := target.TestNewCredentialLibrary("", lib1.PublicId, credential.ApplicationPurpose)
		_, _, _, err := repo.SetTargetCredentialSources(context.Background(), "", 1, []*target.CredentialLibrary{cl1})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "unexpected error %s", err.Error())
	})
	t.Run("target-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		cl1 := target.TestNewCredentialLibrary("fake-target-id", lib1.PublicId, credential.ApplicationPurpose)
		_, _, _, err := repo.SetTargetCredentialSources(context.Background(), "fake-target-id", 1, []*target.CredentialLibrary{cl1})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "unexpected error %s", err.Error())
	})
}
