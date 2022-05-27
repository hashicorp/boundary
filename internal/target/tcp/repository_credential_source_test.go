package tcp_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
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

	csVault := vault.TestCredentialStores(t, conn, wrapper, staticProj.GetPublicId(), 1)[0]
	libs := vault.TestCredentialLibraries(t, conn, wrapper, csVault.GetPublicId(), 3)
	require.Len(t, libs, 3)
	lib1 := libs[0]
	lib2 := libs[1]
	lib3 := libs[2]

	csStatic := static.TestCredentialStore(t, conn, wrapper, staticProj.GetPublicId())
	creds := static.TestUsernamePasswordCredentials(t, conn, wrapper, "user", "pass", csStatic.GetPublicId(), staticProj.GetPublicId(), 3)
	require.Len(t, creds, 3)
	cred1 := creds[0]
	cred2 := creds[1]
	cred3 := creds[2]

	type args struct {
		targetVersion uint32
		ids           target.CredentialSources
	}
	tests := []struct {
		name            string
		args            args
		wantCredSources map[string]target.CredentialSource
		wantErr         bool
		wantErrCode     errors.Code
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
			name: "valid-single-library",
			args: args{
				targetVersion: 1,
				ids:           target.CredentialSources{ApplicationCredentialIds: []string{lib1.PublicId}},
			},
			wantCredSources: map[string]target.CredentialSource{
				lib1.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: lib1.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-single-static",
			args: args{
				targetVersion: 1,
				ids:           target.CredentialSources{ApplicationCredentialIds: []string{cred1.PublicId}},
			},
			wantCredSources: map[string]target.CredentialSource{
				cred1.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: cred1.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-multiple-libraries",
			args: args{
				targetVersion: 1,
				ids:           target.CredentialSources{ApplicationCredentialIds: []string{lib1.PublicId, lib2.PublicId, lib3.PublicId}},
			},
			wantCredSources: map[string]target.CredentialSource{
				lib1.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: lib1.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
				lib2.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: lib2.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
				lib3.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: lib3.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-multiple-static",
			args: args{
				targetVersion: 1,
				ids:           target.CredentialSources{ApplicationCredentialIds: []string{cred1.PublicId, cred2.PublicId, cred3.PublicId}},
			},
			wantCredSources: map[string]target.CredentialSource{
				cred1.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: cred1.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
				cred2.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: cred2.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
				cred3.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: cred3.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-multiple-sources",
			args: args{
				targetVersion: 1,
				ids: target.CredentialSources{
					ApplicationCredentialIds: []string{cred1.PublicId, cred2.PublicId, lib1.PublicId, lib2.PublicId},
				},
			},
			wantCredSources: map[string]target.CredentialSource{
				cred1.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: cred1.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
				cred2.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: cred2.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
				lib1.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: lib1.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
				lib2.PublicId + "_" + string(credential.ApplicationPurpose): &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						CredentialSourceId: lib2.PublicId,
						CredentialPurpose:  string(credential.ApplicationPurpose),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid-source-id",
			args: args{
				targetVersion: 1,
				ids: target.CredentialSources{
					ApplicationCredentialIds: []string{lib1.PublicId, cred2.PublicId, "invalid-source-id", lib3.PublicId, cred3.PublicId},
				},
			},
			wantErr:     true,
			wantErrCode: errors.NotSpecificIntegrity,
		},
		{
			name: "egress-credential-purpose-library",
			args: args{
				targetVersion: 1,
				ids:           target.CredentialSources{EgressCredentialIds: []string{lib1.PublicId}},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "egress-credential-purpose-static",
			args: args{
				targetVersion: 1,
				ids:           target.CredentialSources{EgressCredentialIds: []string{cred1.PublicId}},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "bad-version",
			args: args{
				targetVersion: 1000,
				ids:           target.CredentialSources{ApplicationCredentialIds: []string{lib1.PublicId}},
			},
			wantErr:     true,
			wantErrCode: errors.VersionMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			ctx := context.Background()
			projTarget := tcp.TestTarget(ctx, t, conn, staticProj.PublicId, tt.name)

			gotTarget, _, gotCredSources, err := repo.AddTargetCredentialSources(context.Background(), projTarget.GetPublicId(), tt.args.targetVersion, tt.args.ids)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			assert.Len(gotCredSources, len(tt.wantCredSources))

			for _, cs := range gotCredSources {
				w, ok := tt.wantCredSources[cs.Id()+"_"+string(cs.CredentialPurpose())]
				assert.True(ok, "got unexpected credentialsource %v", cs)
				assert.Equal(w.Id(), cs.Id())
				assert.Equal(w.CredentialPurpose(), cs.CredentialPurpose())
			}

			// test to see of the target version update oplog was created
			err = db.TestVerifyOplog(t, rw, projTarget.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			tar, _, lookupCredSources, err := repo.LookupTarget(context.Background(), projTarget.GetPublicId())
			require.NoError(err)
			assert.Equal(tt.args.targetVersion+1, tar.GetVersion())
			assert.Equal(projTarget.GetVersion(), tar.GetVersion()-1)
			assert.True(proto.Equal(gotTarget.(*tcp.Target), tar.(*tcp.Target)))
			assert.Equal(gotCredSources, lookupCredSources)

			for _, cs := range lookupCredSources {
				w, ok := tt.wantCredSources[cs.Id()+"_"+string(cs.CredentialPurpose())]
				assert.True(ok, "got unexpected credentialsource %v", cs)
				assert.Equal(w.Id(), cs.Id())
				assert.Equal(w.CredentialPurpose(), cs.CredentialPurpose())
				assert.Equal(projTarget.GetPublicId(), cs.TargetId())
			}
		})
	}
	t.Run("add-existing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		ctx := context.Background()
		projTarget := tcp.TestTarget(ctx, t, conn, staticProj.PublicId, "add-existing")

		ids := target.CredentialSources{
			ApplicationCredentialIds: []string{lib1.PublicId},
		}
		_, _, gotCredSources, err := repo.AddTargetCredentialSources(ctx, projTarget.GetPublicId(), 1, ids)
		require.NoError(err)
		assert.Len(gotCredSources, 1)
		assert.Equal(lib1.PublicId, gotCredSources[0].Id())

		// Adding lib1 again should error
		ids = target.CredentialSources{
			ApplicationCredentialIds: []string{lib1.PublicId},
		}
		_, _, _, err = repo.AddTargetCredentialSources(ctx, projTarget.GetPublicId(), 2, ids)
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Adding multiple with lib1 in set should error
		ids = target.CredentialSources{
			ApplicationCredentialIds: []string{lib3.PublicId, lib2.PublicId, lib1.PublicId},
		}
		_, _, _, err = repo.AddTargetCredentialSources(ctx, projTarget.GetPublicId(), 2, ids)
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.NotUnique), err))

		// Previous transactions should have been rolled back and only lib1 should be associated
		_, _, lookupCredSources, err := repo.LookupTarget(ctx, projTarget.GetPublicId())
		require.NoError(err)
		assert.Len(lookupCredSources, 1)
		assert.Equal(lib1.PublicId, lookupCredSources[0].Id())
	})
	t.Run("target-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		ids := target.CredentialSources{
			ApplicationCredentialIds: []string{lib1.PublicId},
		}
		_, _, _, err := repo.AddTargetCredentialSources(context.Background(), "fake-target-id", 1, ids)

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
		createLibCnt          int
		createStaticCnt       int
		deleteLibCnt          int
		deleteStaticCnt       int
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrCode     errors.Code
	}{
		{
			name: "valid-lib-only",
			args: args{
				createLibCnt: 5,
				deleteLibCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-static-only",
			args: args{
				createStaticCnt: 5,
				deleteStaticCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-mixed",
			args: args{
				createLibCnt:    5,
				deleteLibCnt:    5,
				createStaticCnt: 5,
				deleteStaticCnt: 5,
			},
			wantRowsDeleted: 10,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				createLibCnt:    5,
				deleteLibCnt:    3,
				createStaticCnt: 5,
				deleteStaticCnt: 2,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "no-deletes",
			args: args{
				createLibCnt:    5,
				createStaticCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				targetIdOverride: func() *string { id := tcp.TestId(t); return &id }(),
				createLibCnt:     5,
				deleteLibCnt:     5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.RecordNotFound,
		},
		{
			name: "missing-target-id",
			args: args{
				targetIdOverride: func() *string { id := ""; return &id }(),
				createLibCnt:     5,
				deleteLibCnt:     5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				targetVersionOverride: func() *uint32 { v := uint32(0); return &v }(),
				createLibCnt:          5,
				deleteLibCnt:          5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "bad-version",
			args: args{
				targetVersionOverride: func() *uint32 { v := uint32(1000); return &v }(),
				createLibCnt:          5,
				deleteLibCnt:          5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrCode:     errors.VersionMismatch,
		},
	}
	csVault := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), len(tests))
	csStatic := static.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), len(tests))
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			csv := csVault[i]
			css := csStatic[i]

			ctx := context.Background()
			tar := tcp.TestTarget(ctx, t, conn, proj.PublicId, tt.name)

			var ids target.CredentialSources
			credLibs := vault.TestCredentialLibraries(t, conn, wrapper, csv.PublicId, tt.args.createLibCnt)
			for _, cl := range credLibs {
				ids.ApplicationCredentialIds = append(ids.ApplicationCredentialIds, cl.GetPublicId())
			}
			creds := static.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", css.PublicId, proj.GetPublicId(), tt.args.createStaticCnt)
			for _, c := range creds {
				ids.ApplicationCredentialIds = append(ids.ApplicationCredentialIds, c.GetPublicId())
			}

			_, _, addedCredSources, err := repo.AddTargetCredentialSources(ctx, tar.GetPublicId(), 1, ids)
			require.NoError(err)
			assert.Equal(tt.args.createLibCnt+tt.args.createStaticCnt, len(addedCredSources))

			var deleteIds target.CredentialSources
			for i := 0; i < tt.args.deleteLibCnt; i++ {
				deleteIds.ApplicationCredentialIds = append(deleteIds.ApplicationCredentialIds, credLibs[i].GetPublicId())
			}
			for i := 0; i < tt.args.deleteStaticCnt; i++ {
				deleteIds.ApplicationCredentialIds = append(deleteIds.ApplicationCredentialIds, creds[i].GetPublicId())
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
			deletedRows, err := repo.DeleteTargetCredentialSources(ctx, targetId, targetVersion, deleteIds)
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

		ctx := context.Background()
		projTarget := tcp.TestTarget(ctx, t, conn, proj.PublicId, "add-existing")

		ids := target.CredentialSources{
			ApplicationCredentialIds: []string{lib1.GetPublicId(), lib2.GetPublicId()},
		}
		_, _, gotCredSources, err := repo.AddTargetCredentialSources(ctx, projTarget.GetPublicId(), 1, ids)
		require.NoError(err)
		assert.Len(gotCredSources, 2)

		// Deleting an unassociated source should return an error
		delCount, err := repo.DeleteTargetCredentialSources(ctx, projTarget.GetPublicId(), 2,
			target.CredentialSources{
				ApplicationCredentialIds: []string{lib3.GetPublicId()},
			})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Deleting sources which includes an unassociated source should return an error
		delCount, err = repo.DeleteTargetCredentialSources(ctx, projTarget.GetPublicId(), 2,
			target.CredentialSources{
				ApplicationCredentialIds: []string{lib1.GetPublicId(), lib2.GetPublicId(), lib3.GetPublicId()},
			})
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.MultipleRecords), err))
		assert.Equal(0, delCount)

		// Previous transactions should have been rolled back and only lib1 should be associated
		_, _, lookupCredSources, err := repo.LookupTarget(ctx, projTarget.GetPublicId())
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
		var ids target.CredentialSources
		for _, cl := range credLibs {
			cls = append(cls, target.TestNewCredentialLibrary(tar.GetPublicId(), cl.PublicId, credential.ApplicationPurpose))
			ids.ApplicationCredentialIds = append(ids.ApplicationCredentialIds, cl.GetPublicId())
		}

		_, _, created, err := repo.AddTargetCredentialSources(context.Background(), tar.GetPublicId(), 1, ids)
		require.NoError(t, err)
		require.Equal(t, 10, len(created))
		return created, cls
	}
	type args struct {
		targetVersion uint32
		cls           []*target.CredentialLibrary
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
				cls:           []*target.CredentialLibrary{},
			},
			wantErr:          false,
			wantAffectedRows: 10,
		},
		{
			name:  "no-change",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				cls:           []*target.CredentialLibrary{},
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
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", lib2.PublicId, credential.ApplicationPurpose),
				},
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
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", lib2.PublicId, credential.ApplicationPurpose),
				},
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
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", lib2.PublicId, credential.ApplicationPurpose),
				},
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
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", lib2.PublicId, credential.ApplicationPurpose),
				},
				addToOrigLibs: false,
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
		{
			name:  "egress-credential-purpose",
			setup: setupFn,
			args: args{
				targetVersion: 1,
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.EgressPurpose),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:  "ingress-credential-purpose",
			setup: setupFn,
			args: args{
				targetVersion: 1,
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.IngressPurpose),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			ctx := context.Background()
			tar := tcp.TestTarget(ctx, t, conn, proj.PublicId, tt.name)

			var origCredSources []target.CredentialSource
			var origCredLibraries []*target.CredentialLibrary
			if tt.setup != nil {
				origCredSources, origCredLibraries = tt.setup(tar)
			}

			wantCredSources := make(map[string]target.CredentialSource)
			for _, cl := range tt.args.cls {
				cl.TargetId = tar.GetPublicId()
				wantCredSources[cl.CredentialLibraryId+"_"+cl.CredentialPurpose] = &target.TargetCredentialSource{
					CredentialSource: &store.CredentialSource{
						TargetId:           cl.TargetId,
						CredentialSourceId: cl.CredentialLibraryId,
						CredentialPurpose:  cl.CredentialPurpose,
						CreateTime:         cl.CreateTime,
					},
				}
			}
			if tt.args.addToOrigLibs {
				tt.args.cls = append(tt.args.cls, origCredLibraries...)
				for _, cl := range origCredLibraries {
					wantCredSources[cl.CredentialLibraryId+"_"+cl.CredentialPurpose] = &target.TargetCredentialSource{
						CredentialSource: &store.CredentialSource{
							TargetId:           cl.TargetId,
							CredentialSourceId: cl.CredentialLibraryId,
							CredentialPurpose:  cl.CredentialPurpose,
							CreateTime:         cl.CreateTime,
						},
					}
				}
			}

			origTarget, _, lookupCredSources, err := repo.LookupTarget(ctx, tar.GetPublicId())
			require.NoError(err)
			assert.Equal(origCredSources, lookupCredSources)

			_, got, affectedRows, err := repo.SetTargetCredentialSources(ctx, tar.GetPublicId(), tt.args.targetVersion, tt.args.cls)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, affectedRows)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			t.Log(err)
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)

			assert.Equal(len(wantCredSources), len(got))

			for _, cs := range got {
				w, ok := wantCredSources[cs.Id()+"_"+string(cs.CredentialPurpose())]
				assert.True(ok, "got unexpected credentialsource %v", cs)
				assert.Equal(w.Id(), cs.Id())
				assert.Equal(w.CredentialPurpose(), cs.CredentialPurpose())
			}

			foundTarget, _, _, err := repo.LookupTarget(ctx, tar.GetPublicId())
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
