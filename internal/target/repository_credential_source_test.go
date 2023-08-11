// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hooks struct{}

func (h hooks) NewTarget(ctx context.Context, projectId string, opt ...target.Option) (target.Target, error) {
	return targettest.New(ctx, projectId, opt...)
}

func (h hooks) AllocTarget() target.Target {
	return targettest.Alloc()
}

func (h hooks) Vet(ctx context.Context, t target.Target) error {
	return targettest.Vet(ctx, t)
}

func (h hooks) VetForUpdate(ctx context.Context, t target.Target, paths []string) error {
	return targettest.VetForUpdate(ctx, t, paths)
}

func (h hooks) VetCredentialSources(ctx context.Context, cls []*target.CredentialLibrary, creds []*target.StaticCredential) error {
	return targettest.VetCredentialSources(ctx, cls, creds)
}

func TestRepository_SetTargetCredentialSources(t *testing.T) {
	ctx := context.Background()
	target.Register(targettest.Subtype, hooks{}, globals.TcpTargetPrefix)

	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := target.NewRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	storeVault := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	credLibs := vault.TestCredentialLibraries(t, conn, wrapper, storeVault.GetPublicId(), 2)
	lib1 := credLibs[0]
	lib2 := credLibs[1]

	storeStatic := static.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	credsStatic := static.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", storeStatic.GetPublicId(), proj.GetPublicId(), 2)
	cred1 := credsStatic[0]
	cred2 := credsStatic[1]

	setupFn := func(tar target.Target) ([]target.CredentialSource, target.CredentialSources) {
		credLibs := vault.TestCredentialLibraries(t, conn, wrapper, storeVault.GetPublicId(), 5)
		var ids target.CredentialSources
		for _, cl := range credLibs {
			ids.BrokeredCredentialIds = append(ids.BrokeredCredentialIds, cl.GetPublicId())
		}
		creds := static.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", storeStatic.GetPublicId(), proj.GetPublicId(), 5)
		for _, cred := range creds {
			ids.BrokeredCredentialIds = append(ids.BrokeredCredentialIds, cred.GetPublicId())
		}

		target, err := repo.AddTargetCredentialSources(ctx, tar.GetPublicId(), 1, ids)
		require.NoError(t, err)

		credentialSources := target.GetCredentialSources()

		require.Equal(t, 10, len(credentialSources))
		return credentialSources, ids
	}
	type args struct {
		targetVersion    uint32
		ids              target.CredentialSources
		addToOrigSources bool
	}
	tests := []struct {
		name             string
		setup            func(target.Target) ([]target.CredentialSource, target.CredentialSources)
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
			},
			wantErr:          false,
			wantAffectedRows: 10,
		},
		{
			name:  "no-change",
			setup: setupFn,
			args: args{
				targetVersion:    2,
				addToOrigSources: true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "add-cred-library",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{lib1.PublicId, lib2.PublicId},
				},
				addToOrigSources: true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "add-cred-static",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{cred1.PublicId, cred2.PublicId},
				},
				addToOrigSources: true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "add-cred-lib-and-static",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{cred1.PublicId, lib1.PublicId, cred2.PublicId, lib2.PublicId},
				},
				addToOrigSources: true,
			},
			wantErr:          false,
			wantAffectedRows: 4,
		},
		{
			name:  "zero version",
			setup: setupFn,
			args: args{
				targetVersion: 0,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{lib1.PublicId, lib2.PublicId},
				},
				addToOrigSources: true,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:  "bad version",
			setup: setupFn,
			args: args{
				targetVersion: 1000,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{lib1.PublicId, lib2.PublicId},
				},
				addToOrigSources: true,
			},
			wantErr:     true,
			wantErrCode: errors.VersionMismatch,
		},
		{
			name:  "remove existing and add cred libs",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{lib1.PublicId, lib2.PublicId},
				},
				addToOrigSources: false,
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
		{
			name:  "remove existing and add cred static",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{cred1.PublicId, cred2.PublicId},
				},
				addToOrigSources: false,
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
		{
			name:  "remove existing and add cred static and lib",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				ids: target.CredentialSources{
					BrokeredCredentialIds: []string{cred1.PublicId, lib2.PublicId},
				},
				addToOrigSources: false,
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
		{
			name:  "injected-application-credential-purpose",
			setup: setupFn,
			args: args{
				targetVersion: 2,
				ids: target.CredentialSources{
					InjectedApplicationCredentialIds: []string{lib1.PublicId},
				},
				addToOrigSources: true,
			},
			wantAffectedRows: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			ctx := context.Background()
			tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, tt.name)

			var origCredSources []target.CredentialSource
			wantCredSources := make(map[string]target.CredentialSource)
			if tt.setup != nil {
				var origCredIds target.CredentialSources
				origCredSources, origCredIds = tt.setup(tar)

				if tt.args.addToOrigSources {
					tt.args.ids.BrokeredCredentialIds = append(tt.args.ids.BrokeredCredentialIds, origCredIds.BrokeredCredentialIds...)
					tt.args.ids.InjectedApplicationCredentialIds = append(tt.args.ids.InjectedApplicationCredentialIds, origCredIds.InjectedApplicationCredentialIds...)
				}
			}

			byPurpose := map[credential.Purpose][]string{
				credential.BrokeredPurpose:            tt.args.ids.BrokeredCredentialIds,
				credential.InjectedApplicationPurpose: tt.args.ids.InjectedApplicationCredentialIds,
			}
			for purpose, ids := range byPurpose {
				for _, id := range ids {
					wantCredSources[id+"_"+string(purpose)] = &target.TargetCredentialSource{
						CredentialSource: &store.CredentialSource{
							CredentialSourceId: id,
							CredentialPurpose:  string(purpose),
						},
					}
				}
			}

			origTarget, err := repo.LookupTarget(ctx, tar.GetPublicId())
			require.NoError(err)

			assert.Equal(origCredSources, origTarget.GetCredentialSources())

			_, gotSources, affectedRows, err := repo.SetTargetCredentialSources(ctx, tar.GetPublicId(), tt.args.targetVersion, tt.args.ids)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, affectedRows)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err.Error())
				return
			}
			t.Log(err)
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)

			for _, cs := range gotSources {
				w, ok := wantCredSources[cs.Id()+"_"+string(cs.CredentialPurpose())]
				assert.True(ok, "got unexpected credentialsource %v", cs)
				assert.Equal(w.Id(), cs.Id())
				assert.Equal(w.CredentialPurpose(), cs.CredentialPurpose())
			}

			foundTarget, err := repo.LookupTarget(ctx, tar.GetPublicId())
			require.NoError(err)
			if tt.name != "no-change" {
				assert.Equalf(tt.args.targetVersion+1, foundTarget.GetVersion(), "%s unexpected version: %d/%d", tt.name, tt.args.targetVersion+1, foundTarget.GetVersion())
				assert.Equalf(origTarget.GetVersion(), foundTarget.GetVersion()-1, "%s unexpected version: %d/%d", tt.name, origTarget.GetVersion(), foundTarget.GetVersion()-1)
			}
		})
	}
	t.Run("missing-target-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		_, _, _, err := repo.SetTargetCredentialSources(context.Background(), "", 1,
			target.CredentialSources{BrokeredCredentialIds: []string{lib1.PublicId}})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "unexpected error %s", err.Error())
	})
	t.Run("target-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		_, _, _, err := repo.SetTargetCredentialSources(context.Background(), "fake-target-id", 1,
			target.CredentialSources{BrokeredCredentialIds: []string{lib1.PublicId}})

		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "unexpected error %s", err.Error())
	})
}
