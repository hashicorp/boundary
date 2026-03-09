// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	target.Register(targettest.Subtype, hooks{}, globals.TcpTargetPrefix)
}

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

func TestListDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Expect no entries at the start
	deletedIds, ttime := target.TestListDeletedIds(t, repo, ctx, time.Now().AddDate(-1, 0, 0))
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a session
	tg := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "deleteme")
	_, err = repo.DeleteTarget(ctx, tg.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime = target.TestListDeletedIds(t, repo, ctx, time.Now().AddDate(-1, 0, 0))
	require.Equal(t, []string{tg.GetPublicId()}, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime = target.TestListDeletedIds(t, repo, ctx, time.Now())
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestEstimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems := target.TestEstimatedCount(t, repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create a target, expect 1 entries
	tg := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "target1")
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems = target.TestEstimatedCount(t, repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the target, expect 0 again
	_, err = repo.DeleteTarget(ctx, tg.GetPublicId())
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems = target.TestEstimatedCount(t, repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_ListTargets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	_, proj2 := iam.TestScopes(t, iamRepo)

	var total int
	for i := 0; i < 5; i++ {
		targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), fmt.Sprintf("proj1-%d", i))
		total++
		targettest.TestNewTestTarget(ctx, t, conn, proj2.GetPublicId(), fmt.Sprintf("proj2-%d", i))
		total++
	}

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms,
		target.WithPermissions([]perms.Permission{
			{
				GrantScopeId: proj1.PublicId,
				Resource:     resource.Target,
				Action:       action.List,
				All:          true,
			},
			{
				GrantScopeId: proj2.PublicId,
				Resource:     resource.Target,
				Action:       action.List,
				All:          true,
			},
		}),
	)
	require.NoError(t, err)

	t.Run("no-options", func(t *testing.T) {
		got, ttime := target.TestListTargets(t, repo, ctx)
		require.NoError(t, err)
		assert.Equal(t, total, len(got))
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
	})

	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		page1, ttime := target.TestListTargets(
			t,
			repo,
			context.Background(),
			target.WithLimit(2),
		)
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime := target.TestListTargets(
			t,
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page1[1]),
		)
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime := target.TestListTargets(
			t,
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page2[1]),
		)
		require.NoError(err)
		require.Len(page3, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, ttime := target.TestListTargets(
			t,
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page3[1]),
		)
		require.NoError(err)
		require.Len(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, ttime := target.TestListTargets(
			t,
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page4[1]),
		)
		require.NoError(err)
		require.Len(page5, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, ttime := target.TestListTargets(
			t,
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page5[1]),
		)
		require.NoError(err)
		require.Empty(page6)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		// Update the first two targets
		page1[0].SetName("new-name")
		_, _, err = repo.UpdateTarget(ctx, page1[0], page1[0].GetVersion(), []string{"name"})
		require.NoError(err)
		page1[1].SetName("newer-name")
		_, _, err = repo.UpdateTarget(ctx, page1[1], page1[1].GetVersion(), []string{"name"})
		require.NoError(err)

		// since it will return newest to oldest, we get page1[1] first
		page7, ttime := target.TestListTargetsRefresh(
			t,
			repo,
			context.Background(),
			time.Now().Add(-1*time.Second),
			target.WithLimit(1),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), page1[1].GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		page8, ttime := target.TestListTargetsRefresh(
			t,
			repo,
			context.Background(),
			time.Now().Add(-1*time.Second),
			target.WithLimit(1),
			target.WithStartPageAfterItem(page7[0]),
		)
		require.NoError(err)
		require.Len(page8, 1)
		require.Equal(page8[0].GetPublicId(), page1[0].GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func TestRepository_ListTargets_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, proj1 := iam.TestScopes(t, iamRepo)
	_, proj2 := iam.TestScopes(t, iamRepo)

	const numPerScope = 10
	var total int
	for i := 0; i < numPerScope; i++ {
		targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), fmt.Sprintf("proj1-%d", i))
		total++
		targettest.TestNewTestTarget(ctx, t, conn, proj2.GetPublicId(), fmt.Sprintf("proj2-%d", i))
		total++
	}

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms,
		target.WithPermissions([]perms.Permission{
			{
				GrantScopeId: proj1.PublicId,
				Resource:     resource.Target,
				Action:       action.List,
				All:          true,
			},
			{
				GrantScopeId: proj2.PublicId,
				Resource:     resource.Target,
				Action:       action.List,
				All:          true,
			},
		}),
	)
	require.NoError(t, err)

	got, ttime := target.TestListTargets(t, repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestRepository_ListRoles_Above_Default_Count(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iamRepo)

	numToCreate := db.DefaultLimit + 5
	var total int
	for i := 0; i < numToCreate; i++ {
		targettest.TestNewTestTarget(ctx, t, conn, proj.GetPublicId(), fmt.Sprintf("proj1-%d", i), target.WithAddress("1.2.3.4"))
		total++
	}
	require.Equal(t, numToCreate, total)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms,
		target.WithPermissions([]perms.Permission{
			{
				GrantScopeId: proj.PublicId,
				Resource:     resource.Target,
				Action:       action.List,
				All:          true,
			},
		}))
	require.NoError(t, err)

	got, ttime := target.TestListTargets(t, repo, ctx, target.WithLimit(numToCreate))
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	for _, tar := range got {
		assert.Equal(t, "1.2.3.4", tar.GetAddress())
	}
}

func TestRepository_SetTargetCredentialSources(t *testing.T) {
	ctx := context.Background()

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
	credLibs := vault.TestCredentialLibraries(t, conn, wrapper, storeVault.GetPublicId(), globals.UnspecifiedCredentialType, 2)
	lib1 := credLibs[0]
	lib2 := credLibs[1]

	storeStatic := static.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	credsStatic := static.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", storeStatic.GetPublicId(), proj.GetPublicId(), 2)
	cred1 := credsStatic[0]
	cred2 := credsStatic[1]

	setupFn := func(tar target.Target) ([]target.CredentialSource, target.CredentialSources) {
		credLibs := vault.TestCredentialLibraries(t, conn, wrapper, storeVault.GetPublicId(), globals.UnspecifiedCredentialType, 5)
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
