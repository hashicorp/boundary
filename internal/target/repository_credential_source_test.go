package target_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_SetTargetCredentialSources(t *testing.T) {
	target.Register(targettest.Subtype, targettest.New, targettest.Alloc, targettest.Vet, targettest.VetCredentialLibraries, targettest.TargetPrefix)

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
			name:  "add-multiple-purposes",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.EgressPurpose),
					target.TestNewCredentialLibrary("", lib2.PublicId, credential.ApplicationPurpose),
				},
				addToOrigLibs: true,
			},
			wantErr:          false,
			wantAffectedRows: 3,
		},
		{
			name: "remove-add-change-purpose",
			setup: func(tar target.Target) ([]target.CredentialSource, []*target.CredentialLibrary) {
				cls := []*target.CredentialLibrary{
					target.TestNewCredentialLibrary(tar.GetPublicId(), lib1.PublicId, credential.ApplicationPurpose),
					target.TestNewCredentialLibrary(tar.GetPublicId(), lib2.PublicId, credential.ApplicationPurpose),
				}

				_, _, created, err := repo.AddTargetCredentialSources(context.Background(), tar.GetPublicId(), 1, cls)
				require.NoError(t, err)
				require.Equal(t, 2, len(created))
				return created, cls
			},
			args: args{
				targetVersion: 2,
				cls: []*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", lib1.PublicId, credential.EgressPurpose),
					target.TestNewCredentialLibrary("", lib2.PublicId, credential.EgressPurpose),
				},
				addToOrigLibs: false,
			},
			wantErr:          false,
			wantAffectedRows: 4,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			ctx := context.Background()
			tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, tt.name)

			var origCredSources []target.CredentialSource
			var origCredLibraries []*target.CredentialLibrary
			if tt.setup != nil {
				origCredSources, origCredLibraries = tt.setup(tar)
			}

			wantCredSources := make(map[string]target.CredentialSource)
			for _, cl := range tt.args.cls {
				cl.TargetId = tar.GetPublicId()
				wantCredSources[cl.CredentialLibraryId+"_"+cl.CredentialPurpose] = &target.TargetLibrary{
					CredentialLibrary: cl.CredentialLibrary,
				}
			}
			if tt.args.addToOrigLibs {
				tt.args.cls = append(tt.args.cls, origCredLibraries...)
				for _, cl := range origCredLibraries {
					wantCredSources[cl.CredentialLibraryId+"_"+cl.CredentialPurpose] = &target.TargetLibrary{
						CredentialLibrary: cl.CredentialLibrary,
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
