package target

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_AddTargetCredentialLibraries(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, staticProj := iam.TestScopes(t, iamRepo)
	repo, err := NewRepository(rw, rw, testKms)
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
			name: "no-cred-libs",
			args: args{
				targetVersion: 1,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid-single-lib",
			args: args{
				targetVersion: 1,
				credLibIds:    []string{lib1.PublicId},
			},
			wantCredLibIds: []string{lib1.PublicId},
			wantErr:        false,
		},
		{
			name: "valid-multiple-libs",
			args: args{
				targetVersion: 1,
				credLibIds:    []string{lib1.PublicId, lib2.PublicId, lib3.PublicId},
			},
			wantCredLibIds: []string{lib1.PublicId, lib2.PublicId, lib3.PublicId},
			wantErr:        false,
		},
		{
			name: "invalid-lib-id",
			args: args{
				targetVersion: 1,
				credLibIds:    []string{lib1.PublicId, lib2.PublicId, lib3.PublicId, "invalid-lib-id"},
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

			projTarget := TestTcpTarget(t, conn, staticProj.PublicId, tt.name)
			gotTarget, gotCredLibs, err := repo.AddTargetCredentialLibraries(context.Background(), projTarget.PublicId, tt.args.targetVersion, tt.args.credLibIds)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			assert.Len(gotCredLibs, len(tt.wantCredLibIds))
			gotCredLibsMap := map[string]*CredentialLibrary{}
			for _, s := range gotCredLibs {
				gotCredLibsMap[s.CredentialLibraryId] = s
			}
			for _, id := range tt.wantCredLibIds {
				assert.NotEmpty(gotCredLibsMap[id])
			}

			// test to see of the target version update oplog was created
			err = db.TestVerifyOplog(t, rw, projTarget.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundCredLibs, err := fetchLibraries(context.Background(), rw, projTarget.PublicId)
			require.NoError(err)
			assert.Len(foundCredLibs, len(gotCredLibsMap))
			for _, s := range foundCredLibs {
				assert.NotEmpty(gotCredLibsMap[s.CredentialLibraryId])
				assert.Equal(projTarget.PublicId, s.TargetId)
			}

			target, _, err := repo.LookupTarget(context.Background(), projTarget.PublicId)
			require.NoError(err)
			assert.Equal(tt.args.targetVersion+1, target.GetVersion())
			assert.Equal(projTarget.GetVersion(), target.GetVersion()-1)
			assert.True(proto.Equal(gotTarget.(*TcpTarget), target.(*TcpTarget)))
		})
	}
	t.Run("target-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		_, _, err := repo.AddTargetCredentialLibraries(context.Background(), "fake-target-id", 1, []string{lib1.PublicId})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "unexpected error %s", err.Error())
	})
}

func TestRepository_DeleteTargetCredentialLibraries(t *testing.T) {
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
				targetIdOverride: func() *string { id := testId(t); return &id }(),
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			target := TestTcpTarget(t, conn, proj.PublicId, tt.name)

			clIds := make([]string, 0, tt.args.createCnt)
			if tt.args.createCnt > 0 {
				cs := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
				credLibs := vault.TestCredentialLibraries(t, conn, wrapper, cs.PublicId, tt.args.createCnt)
				for _, cl := range credLibs {
					clIds = append(clIds, cl.PublicId)
				}
			}
			_, addedCredLibs, err := repo.AddTargetCredentialLibraries(context.Background(), target.GetPublicId(), 1, clIds)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(addedCredLibs))

			deleteCredLibs := make([]string, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteCredLibs = append(deleteCredLibs, clIds[i])
			}
			var targetId string
			switch {
			case tt.args.targetIdOverride != nil:
				targetId = *tt.args.targetIdOverride
			default:
				targetId = target.GetPublicId()
			}
			var targetVersion uint32
			switch {
			case tt.args.targetVersionOverride != nil:
				targetVersion = *tt.args.targetVersionOverride
			default:
				targetVersion = 2
			}
			deletedRows, err := repo.DeleteTargetCredentialLibraries(context.Background(), targetId, targetVersion, deleteCredLibs)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			// we should find the oplog for the delete of target credential libraries
			err = db.TestVerifyOplog(t, rw, target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_SetTargetCredentialLibraries(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	cs := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	credLibs := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)
	lib1 := credLibs[0]
	lib2 := credLibs[1]

	setupFn := func(target Target) []*CredentialLibrary {
		credLibs := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 10)
		clIds := make([]string, 0, len(credLibs))
		for _, cl := range credLibs {
			clIds = append(clIds, cl.PublicId)
		}

		_, created, err := repo.AddTargetCredentialLibraries(context.Background(), target.GetPublicId(), 1, clIds)
		require.NoError(t, err)
		require.Equal(t, 10, len(created))
		return created
	}
	type args struct {
		targetVersion uint32
		clIds         []string
		addToOrigLibs bool
	}
	tests := []struct {
		name             string
		setup            func(Target) []*CredentialLibrary
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
			name:  "add-sets",
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
			name:  "remove existing and add users and grps",
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

			target := TestTcpTarget(t, conn, proj.PublicId, tt.name)

			var origCredLibs []*CredentialLibrary
			if tt.setup != nil {
				origCredLibs = tt.setup(target)
			}
			if tt.args.addToOrigLibs {
				origIds := make([]string, 0, len(origCredLibs))
				for _, cl := range origCredLibs {
					origIds = append(origIds, cl.CredentialLibraryId)
				}
				tt.args.clIds = append(tt.args.clIds, origIds...)
			}

			origTarget, _, err := repo.LookupTarget(context.Background(), target.GetPublicId())
			require.NoError(err)

			got, affectedRows, err := repo.SetTargetCredentialLibraries(context.Background(), target.GetPublicId(), tt.args.targetVersion, tt.args.clIds)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, affectedRows)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			t.Log(err)
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)
			assert.Equal(len(tt.args.clIds), len(got))

			var wantIds []string
			wantIds = append(wantIds, tt.args.clIds...)
			sort.Strings(wantIds)

			var gotIds []string
			if len(got) > 0 {
				gotIds = make([]string, 0, len(got))
				for _, s := range got {
					gotIds = append(gotIds, s.CredentialLibraryId)
				}
			}
			sort.Strings(gotIds)
			assert.Equal(wantIds, gotIds)

			foundTarget, _, err := repo.LookupTarget(context.Background(), target.GetPublicId())
			require.NoError(err)
			if tt.name != "no-change" {
				assert.Equalf(tt.args.targetVersion+1, foundTarget.GetVersion(), "%s unexpected version: %d/%d", tt.name, tt.args.targetVersion+1, foundTarget.GetVersion())
				assert.Equalf(origTarget.GetVersion(), foundTarget.GetVersion()-1, "%s unexpected version: %d/%d", tt.name, origTarget.GetVersion(), foundTarget.GetVersion()-1)
			}
		})
	}
	t.Run("missing-target-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		_, _, err := repo.SetTargetCredentialLibraries(context.Background(), "", 1, []string{lib1.PublicId})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "unexpected error %s", err.Error())
	})
	t.Run("target-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		_, _, err := repo.SetTargetCredentialLibraries(context.Background(), "fake-target-id", 1, []string{lib1.PublicId})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "unexpected error %s", err.Error())
	})
}
