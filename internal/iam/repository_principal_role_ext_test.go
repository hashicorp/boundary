// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_PrincipalsToSet(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")

	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)

	repo := iam.TestRepo(t, conn, wrap)
	org, proj := iam.TestScopes(t, repo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	createUsersFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			u := iam.TestUser(t, repo, org.PublicId)
			results = append(results, u.PublicId)
		}
		return results
	}
	createGrpsFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			g := iam.TestGroup(t, conn, proj.PublicId)
			results = append(results, g.PublicId)
		}
		return results
	}
	createManagedGrpsFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			g := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
			results = append(results, g.PublicId)
		}
		return results
	}
	setupFn := func() (*iam.Role, []string, []string, []string) {
		users := createUsersFn()
		grps := createGrpsFn()
		managedGrps := createManagedGrpsFn()
		role := iam.TestRole(t, conn, proj.PublicId)
		_, err := repo.AddPrincipalRoles(context.Background(), role.PublicId, 1, append(users, append(grps, managedGrps...)...))
		require.NoError(t, err)
		return role, users, grps, managedGrps
	}

	type args struct {
		userIds         []string
		groupIds        []string
		managedGroupIds []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "all new",
			args: args{
				userIds:         createUsersFn(),
				groupIds:        createGrpsFn(),
				managedGroupIds: createManagedGrpsFn(),
			},
			wantErr: false,
		},
		{
			name: "clear all",
			args: args{
				userIds:         nil,
				groupIds:        nil,
				managedGroupIds: nil,
			},
			wantErr: false,
		},
		{
			name: "just new users",
			args: args{
				userIds:         createUsersFn(),
				groupIds:        nil,
				managedGroupIds: nil,
			},
			wantErr: false,
		},
		{
			name: "just new groups",
			args: args{
				userIds:         nil,
				groupIds:        createGrpsFn(),
				managedGroupIds: nil,
			},
			wantErr: false,
		},
		{
			name: "just new managed groups",
			args: args{
				userIds:         nil,
				groupIds:        nil,
				managedGroupIds: createManagedGrpsFn(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			r, origUsers, origGrps, origManagedGrps := setupFn()
			got, err := repo.PrincipalsToSet(context.Background(), r, tt.args.userIds, tt.args.groupIds, tt.args.managedGroupIds)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assertSetResults(t, got, tt.args.userIds, tt.args.groupIds, tt.args.managedGroupIds, origUsers, origGrps, origManagedGrps)
		})
	}
	t.Run("nil role", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, users, grps, managedGrps := setupFn()
		got, err := repo.PrincipalsToSet(context.Background(), nil, users, grps, managedGrps)
		require.Error(err)
		assert.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "unexpected error %s", err.Error())
	})
	t.Run("no change", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r, users, grps, managedGrps := setupFn()
		got, err := repo.PrincipalsToSet(context.Background(), r, users, grps, managedGrps)
		require.NoError(err)
		assert.Empty(got.AddUserRoles)
		assert.Empty(got.AddGroupRoles)
		assert.Empty(got.AddManagedGroupRoles)
		assert.Empty(got.DeleteUserRoles)
		assert.Empty(got.DeleteGroupRoles)
		assert.Empty(got.DeleteManagedGroupRoles)
		assert.Equal(len(users)+len(grps)+len(managedGrps), len(got.UnchangedPrincipalRoles))
	})
	t.Run("mixed", func(t *testing.T) {
		require := require.New(t)
		r, users, grps, managedGrps := setupFn()
		var wantSetUsers, wantSetGrps, wantSetManagedGrps, wantDeleteUsers, wantDeleteGrps, wantDeleteManagedGrps []string
		for i, id := range users {
			if i < 2 {
				wantSetUsers = append(wantSetUsers, id)
			} else {
				wantDeleteUsers = append(wantDeleteUsers, id)
			}
		}
		for i, id := range grps {
			if i < 2 {
				wantSetGrps = append(wantSetGrps, id)
			} else {
				wantDeleteGrps = append(wantDeleteGrps, id)
			}
		}
		for i, id := range managedGrps {
			if i < 2 {
				wantSetManagedGrps = append(wantSetManagedGrps, id)
			} else {
				wantDeleteManagedGrps = append(wantDeleteManagedGrps, id)
			}
		}
		newUser := iam.TestUser(t, repo, org.PublicId)
		newGrp := iam.TestGroup(t, conn, proj.PublicId)
		newManagedGrp := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		wantSetUsers = append(wantSetUsers, newUser.PublicId)
		wantSetGrps = append(wantSetGrps, newGrp.PublicId)
		wantSetManagedGrps = append(wantSetManagedGrps, newManagedGrp.PublicId)

		got, err := repo.PrincipalsToSet(context.Background(), r, wantSetUsers, wantSetGrps, wantSetManagedGrps)
		require.NoError(err)
		assertSetResults(t, got, []string{newUser.PublicId}, []string{newGrp.PublicId}, []string{newManagedGrp.PublicId}, wantDeleteUsers, wantDeleteGrps, wantDeleteManagedGrps)
	})
}

func assertSetResults(t *testing.T, got *iam.PrincipalSet, wantAddUsers, wantAddGroups, wantAddManagedGroups, wantDeleteUsers, wantDeleteGroups, wantDeleteManagedGroups []string) {
	t.Helper()
	assert := assert.New(t)
	var gotAddUsers []string
	for _, r := range got.AddUserRoles {
		gotAddUsers = append(gotAddUsers, r.PrincipalId)
	}
	// sort.Strings(wantAddUsers)
	// sort.Strings(gotAddUsers)
	assert.Equal(wantAddUsers, gotAddUsers)

	var gotAddGrps []string
	for _, r := range got.AddGroupRoles {
		gotAddGrps = append(gotAddGrps, r.PrincipalId)
	}
	// sort.Strings(wantAddGroups)
	// sort.Strings(gotAddGrps)
	assert.Equal(wantAddGroups, gotAddGrps)

	var gotAddManagedGrps []string
	for _, r := range got.AddManagedGroupRoles {
		gotAddManagedGrps = append(gotAddManagedGrps, r.PrincipalId)
	}
	// sort.Strings(wantAddGroups)
	// sort.Strings(gotAddGrps)
	assert.Equal(wantAddManagedGroups, gotAddManagedGrps)

	var gotDeleteUsers []string
	for _, r := range got.DeleteUserRoles {
		gotDeleteUsers = append(gotDeleteUsers, r.PrincipalId)
	}
	sort.Strings(wantDeleteUsers)
	sort.Strings(gotDeleteUsers)
	assert.Equal(wantDeleteUsers, gotDeleteUsers)

	var gotDeleteGroups []string
	for _, r := range got.DeleteGroupRoles {
		gotDeleteGroups = append(gotDeleteGroups, r.PrincipalId)
	}
	sort.Strings(wantDeleteGroups)
	sort.Strings(gotDeleteGroups)
	assert.Equal(wantDeleteGroups, gotDeleteGroups)

	var gotDeleteManagedGroups []string
	for _, r := range got.DeleteManagedGroupRoles {
		gotDeleteManagedGroups = append(gotDeleteManagedGroups, r.PrincipalId)
	}
	sort.Strings(wantDeleteManagedGroups)
	sort.Strings(gotDeleteManagedGroups)
	assert.Equal(wantDeleteManagedGroups, gotDeleteManagedGroups)
}
