// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddRoleGrants(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
	role := TestRole(t, conn, proj.PublicId)
	createGrantsFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			g := fmt.Sprintf("ids=hc_%d;actions=*", i)
			results = append(results, g)
		}
		return results
	}
	type args struct {
		roleId      string
		roleVersion uint32
		grants      []string
		opt         []Option
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
				roleId:      role.PublicId,
				roleVersion: 1,
				grants:      createGrantsFn(),
			},
			wantErr: false,
		},
		{
			name: "no-grants",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 2,
				grants:      nil,
			},
			wantErr: true,
		},
		{
			name: "bad-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1000,
				grants:      createGrantsFn(),
			},
			wantErr: true,
		},
		{
			name: "zero-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 0,
				grants:      createGrantsFn(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { rg := allocRoleGrant(); return &rg }(), "1=1")
			got, err := repo.AddRoleGrants(context.Background(), tt.args.roleId, tt.args.roleVersion, tt.args.grants, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			gotRoleGrant := map[string]*RoleGrant{}
			for _, r := range got {
				gotRoleGrant[r.CanonicalGrant] = r
			}

			err = db.TestVerifyOplog(t, rw, role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundRoleGrants, err := repo.ListRoleGrants(context.Background(), role.PublicId)
			require.NoError(err)
			// Create a map of grants to check against
			grantSet := make(map[string]bool, len(tt.args.grants))
			for _, grant := range tt.args.grants {
				grantSet[grant] = true
			}
			for _, r := range foundRoleGrants {
				roleGrant := gotRoleGrant[r.CanonicalGrant]
				assert.NotEmpty(roleGrant)
				assert.Equal(roleGrant.GetRoleId(), r.GetRoleId())
				assert.NotEmpty(grantSet[roleGrant.CanonicalGrant])
				delete(grantSet, roleGrant.CanonicalGrant)
			}
			assert.Empty(grantSet)
		})
	}
}

func TestRepository_ListRoleGrants(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	org, proj := TestScopes(t, repo)

	type args struct {
		withRoleId string
		opt        []Option
	}
	tests := []struct {
		name               string
		createCnt          int
		createGrantScopeId string
		args               args
		wantCnt            int
		wantErr            bool
	}{
		{
			name:               "no-limit",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 2,
			wantErr: false,
		},
		{
			name:               "no-limit-proj-group",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 2,
			wantErr: false,
		},
		{
			name:               "default-limit",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: org.PublicId,
			wantCnt:            repo.defaultLimit,
			wantErr:            false,
		},
		{
			name:               "custom-limit",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:               "bad-role-id",
			createCnt:          2,
			createGrantScopeId: org.PublicId,
			args: args{
				withRoleId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { i := allocGlobalRole(); return &i }(), "1=1")
			db.TestDeleteWhere(t, conn, func() any { i := allocOrgRole(); return &i }(), "1=1")
			db.TestDeleteWhere(t, conn, func() any { i := allocProjectRole(); return &i }(), "1=1")
			role := TestRole(t, conn, tt.createGrantScopeId)
			roleGrants := make([]string, 0, tt.createCnt)
			for i := 0; i < tt.createCnt; i++ {
				roleGrants = append(roleGrants, fmt.Sprintf("ids=h_%d;actions=*", i))
			}
			testRoles, err := repo.AddRoleGrants(context.Background(), role.PublicId, role.Version, roleGrants, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.createCnt, len(testRoles))

			var roleId string
			switch {
			case tt.args.withRoleId != "":
				roleId = tt.args.withRoleId
			default:
				roleId = role.PublicId
			}
			got, err := repo.ListRoleGrants(context.Background(), roleId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_DeleteRoleGrants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	type args struct {
		role                 *Role
		roleIdOverride       *string
		roleVersionOverride  *uint32
		grantStringsOverride []string
		createCnt            int
		deleteCnt            int
		opt                  []Option
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
				role:      TestRole(t, conn, org.PublicId),
				createCnt: 5,
				deleteCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				role:      TestRole(t, conn, org.PublicId),
				createCnt: 5,
				deleteCnt: 3,
			},
			wantRowsDeleted: 3,
			wantErr:         false,
		},

		{
			name: "no-deletes",
			args: args{
				role:      TestRole(t, conn, org.PublicId),
				createCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},

		{
			name: "not-found",
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleIdOverride: func() *string { id := testId(t); return &id }(),
				createCnt:      5,
				deleteCnt:      5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "missing-role-id",
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleIdOverride: func() *string { id := ""; return &id }(),
				createCnt:      5,
				deleteCnt:      5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "invalid-grant-strings",
			args: args{
				role:                 TestRole(t, conn, org.PublicId),
				grantStringsOverride: []string{"ids=s_87;actions=*"},
				createCnt:            5,
				deleteCnt:            3,
			},
			wantRowsDeleted: 2,
		},
		{
			name: "zero-version",
			args: args{
				role:                TestRole(t, conn, org.PublicId),
				createCnt:           5,
				deleteCnt:           5,
				roleVersionOverride: func() *uint32 { v := uint32(0); return &v }(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "bad-version",
			args: args{
				role:                TestRole(t, conn, org.PublicId),
				createCnt:           5,
				deleteCnt:           5,
				roleVersionOverride: func() *uint32 { v := uint32(1000); return &v }(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { rg := allocRoleGrant(); return &rg }(), "1=1")
			grants := make([]*RoleGrant, 0, tt.args.createCnt)
			grantStrings := make([]string, 0, tt.args.createCnt)
			for i := 0; i < tt.args.createCnt; i++ {
				g, err := NewRoleGrant(ctx, tt.args.role.PublicId, fmt.Sprintf("actions=*;ids=s_%d", i), tt.args.opt...)
				require.NoError(err)
				grantStrings = append(grantStrings, g.RawGrant)
				grants = append(grants, g)
			}
			roleGrants, err := repo.AddRoleGrants(context.Background(), tt.args.role.PublicId, 1, grantStrings, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(roleGrants))

			deleteCanonicalGrants := make([]string, 0, tt.args.deleteCnt)
			deleteGrants := make([]string, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteCanonicalGrants = append(deleteCanonicalGrants, grants[i].CanonicalGrant)
				deleteGrants = append(deleteGrants, fmt.Sprintf("ids=s_%d;actions=*", i))
			}
			for i, override := range tt.args.grantStringsOverride {
				deleteCanonicalGrants = deleteCanonicalGrants[1:]
				deleteGrants[i] = override
			}

			var roleId string
			switch {
			case tt.args.roleIdOverride != nil:
				roleId = *tt.args.roleIdOverride
			default:
				roleId = tt.args.role.PublicId
			}
			var roleVersion uint32
			switch {
			case tt.args.roleVersionOverride != nil:
				roleVersion = *tt.args.roleVersionOverride
			default:
				roleVersion = 2
			}
			deletedRows, err := repo.DeleteRoleGrants(context.Background(), roleId, roleVersion, deleteGrants, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "unexpected error %s", err.Error())
				err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			roleGrants = []*RoleGrant{}
			require.NoError(repo.reader.SearchWhere(context.Background(), &roleGrants, "role_id = ?", []any{roleId}))
			found := map[string]bool{}
			for _, rg := range roleGrants {
				found[rg.CanonicalGrant] = true
			}
			for _, i := range deleteCanonicalGrants {
				assert.False(found[i])
			}

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_SetRoleGrants_Randomize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	role := TestRole(t, conn, org.PublicId)
	db.TestDeleteWhere(t, conn, func() any { i := allocRoleGrant(); return &i }(), "1=1")

	type roleGrantWrapper struct {
		grantString string
		enabled     bool
	}

	totalCnt := 30
	grants := make([]*roleGrantWrapper, 0, totalCnt)
	for i := 0; i < totalCnt; i++ {
		g, err := NewRoleGrant(ctx, role.PublicId, fmt.Sprintf("ids=s_%d;actions=*", i))
		require.NoError(err)
		grants = append(grants, &roleGrantWrapper{
			grantString: g.RawGrant,
		})
	}

	// Each loop will set some number of role grants to enabled or disabled
	// randomly and then validate after setting that what's set matches
	var grantsToSet []string
	var expected map[string]bool
	for i := 1; i <= totalCnt; i++ {
		grantsToSet = make([]string, 0, totalCnt)
		expected = make(map[string]bool, totalCnt)
		prng := rand.New(rand.NewSource(time.Now().UnixNano()))
		for _, rgw := range grants {
			rgw.enabled = prng.Int()%2 == 0
			if rgw.enabled {
				grantsToSet = append(grantsToSet, rgw.grantString)
				expected[rgw.grantString] = true
			}
		}

		// First time, run a couple of error conditions
		if i == 1 {
			_, _, err := repo.SetRoleGrants(ctx, "", 1, []string{})
			require.Error(err)
			_, _, err = repo.SetRoleGrants(ctx, role.PublicId, 1, nil)
			require.Error(err)
		}

		_, _, err := repo.SetRoleGrants(ctx, role.PublicId, uint32(i), grantsToSet)
		require.NoError(err)

		roleGrants, err := repo.ListRoleGrants(ctx, role.PublicId)
		require.NoError(err)
		require.Equal(len(grantsToSet), len(roleGrants))
		for _, rg := range roleGrants {
			require.Contains(expected, rg.CanonicalGrant)
			delete(expected, rg.CanonicalGrant)
		}
		require.Empty(expected)
	}

	// At the end, set to explicitly empty and make sure all are cleared out
	_, _, err := repo.SetRoleGrants(context.Background(), role.PublicId, uint32(totalCnt+1), []string{})
	require.NoError(err)

	roleGrants, err := repo.ListRoleGrants(context.Background(), role.PublicId)
	require.NoError(err)
	require.Empty(roleGrants)
}

func TestRepository_SetRoleGrants_Parameters(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	role := TestRole(t, conn, org.PublicId)
	type args struct {
		roleId      string
		roleVersion uint32
		grants      []string
		opt         []Option
	}
	tests := []struct {
		name             string
		args             args
		want             []*RoleGrant
		wantAffectedRows int
		wantErr          bool
	}{
		{
			name: "missing-roleid",
			args: args{
				roleId:      "",
				roleVersion: 1,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "bad-roleid",
			args: args{
				roleId:      "bad-roleid",
				roleVersion: 1,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "nil-grants",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1,
				grants:      nil,
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "zero-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 0,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "bad-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1000,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rg := allocRoleGrant()
			db.TestDeleteWhere(t, conn, &rg, "1=1")
			got, gotAffectedRows, err := repo.SetRoleGrants(context.Background(), tt.args.roleId, tt.args.roleVersion, tt.args.grants, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
			}
			assert.Equal(tt.wantAffectedRows, gotAffectedRows)
			assert.Equal(tt.want, got)
		})
	}
}

// testInput is used to pass test inputs into the various grantsForUser functions
type testInput struct {
	userId     string
	reqScopeId string
	resource   []resource.Type
}

func TestResolveQuery(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)

	scopeSuffix := "_12345"

	testcases := []struct {
		name        string
		input       testInput
		isRecursive bool
		wantQuery   string
		errorMsg    string
	}{
		{
			name: "global request scope should return the global query",
			input: testInput{
				resource:   []resource.Type{resource.Alias},
				reqScopeId: globals.GlobalPrefix,
			},
			wantQuery: grantsForUserGlobalResourcesQuery,
		},
		{
			name: "org request scope should return the org query",
			input: testInput{
				resource:   []resource.Type{resource.AuthToken},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			wantQuery: grantsForUserOrgResourcesQuery,
		},
		{
			name: "project request scope should return the project query",
			input: testInput{
				resource:   []resource.Type{resource.HostCatalog},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			wantQuery: grantsForUserProjectResourcesQuery,
		},
		{
			name: "recursive request should return the recursive query regardless of request scope",
			input: testInput{
				resource:   []resource.Type{resource.HostCatalog},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForUserRecursiveQuery,
		},
		{
			name: "missing resource type should return an error",
			input: testInput{
				reqScopeId: globals.GlobalPrefix,
			},
			errorMsg: "missing resource type",
		},
		{
			name: "unknown resource type should return an error",
			input: testInput{
				resource:   []resource.Type{resource.Unknown},
				reqScopeId: globals.GlobalPrefix,
			},
			errorMsg: "resource type cannot be unknown",
		},
		{
			name: "all resource type should return an error",
			input: testInput{
				resource:   []resource.Type{resource.All},
				reqScopeId: globals.GlobalPrefix,
			},
			errorMsg: "resource type cannot be all",
		},
		{
			name: "missing request scope should return an error",
			input: testInput{
				resource: []resource.Type{resource.Alias},
			},
			errorMsg: "missing request scope id",
		},
		{
			name: "invalid resource type returns error",
			input: testInput{
				resource:   []resource.Type{resource.Type(999)},
				reqScopeId: globals.GlobalPrefix,
			},
			errorMsg: "invalid resource type: 999",
		},
		{
			name: "global resources without a global request scope returns error",
			input: testInput{
				resource:   []resource.Type{resource.Alias, resource.Billing},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			errorMsg: fmt.Sprintf("request scope id must be global for %s resources", []resource.Type{resource.Alias, resource.Billing}),
		},
		{
			name: "global and org resources without a global or org request scope returns error",
			input: testInput{
				resource:   []resource.Type{resource.Account, resource.AuthMethod, resource.AuthToken, resource.ManagedGroup, resource.Policy, resource.SessionRecording, resource.StorageBucket, resource.User},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			errorMsg: fmt.Sprintf("request scope id must be global or org for %s resources", []resource.Type{resource.Account, resource.AuthMethod, resource.AuthToken, resource.ManagedGroup, resource.Policy, resource.SessionRecording, resource.StorageBucket, resource.User}),
		},
		{
			name: "global and org and project resources without a global or org or project request scope returns error",
			input: testInput{
				resource:   []resource.Type{resource.Group, resource.Role, resource.Scope},
				reqScopeId: "junk scope",
			},
			errorMsg: "invalid scope id junk scope",
		},
		{
			name: "project resources without a project request scope returns error",
			input: testInput{
				resource:   []resource.Type{resource.CredentialLibrary, resource.Credential, resource.CredentialStore, resource.HostCatalog, resource.HostSet, resource.Host, resource.Session, resource.Target},
				reqScopeId: globals.GlobalPrefix,
			},
			errorMsg: fmt.Sprintf("request scope id must be project for %s resources", []resource.Type{resource.CredentialLibrary, resource.Credential, resource.CredentialStore, resource.HostCatalog, resource.HostSet, resource.Host, resource.Session, resource.Target}),
		},
		{
			name: "global resource followed by a project resource returns the global query",
			input: testInput{
				resource:   []resource.Type{resource.Alias, resource.Host},
				reqScopeId: globals.GlobalPrefix,
			},
			wantQuery: grantsForUserGlobalResourcesQuery,
		},
		{
			name: "project resource followed by a global resource returns the project query",
			input: testInput{
				resource:   []resource.Type{resource.Host, resource.Alias},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			wantQuery: grantsForUserProjectResourcesQuery,
		},
		{
			name: "global and org resource followed by a global resource returns the org query for an org request scope",
			input: testInput{
				resource:   []resource.Type{resource.AuthMethod, resource.Alias},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			wantQuery: grantsForUserOrgResourcesQuery,
		},
		{
			name: "global and org and project resource followed by a project resource returns the org query for an org request scope",
			input: testInput{
				resource:   []resource.Type{resource.Group, resource.Host},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			wantQuery: grantsForUserOrgResourcesQuery,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			gotQuery, err := repo.resolveQuery(ctx, tc.input.resource, tc.input.reqScopeId, tc.isRecursive)
			if tc.errorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, gotQuery, tc.wantQuery)
		})
	}
}

func TestGrantsForUserGlobalResources(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	user := TestUser(t, repo, globals.GlobalPrefix)

	// Create scopes
	org1 := TestOrg(t, repo)
	org2 := TestOrg(t, repo)

	// Create roles
	roleThis := TestRole(t, conn, globals.GlobalPrefix)
	roleOrg1 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId}))
	roleThisAndOrg2 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, org2.PublicId}))
	roleDescendants := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeDescendants}))
	roleThisAndChildren := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))

	// Grant roles
	TestRoleGrant(t, conn, roleThis.PublicId, "ids=*;type=*;actions=*")
	TestRoleGrant(t, conn, roleOrg1.PublicId, "ids=*;type=alias;actions=create,update,read,list")
	TestRoleGrant(t, conn, roleOrg1.PublicId, "ids=*;type=alias;actions=delete")
	TestRoleGrant(t, conn, roleThisAndOrg2.PublicId, "ids=*;type=alias;actions=delete")
	TestRoleGrant(t, conn, roleThisAndOrg2.PublicId, "ids=*;type=alias;actions=read")
	TestRoleGrant(t, conn, roleThisAndOrg2.PublicId, "ids=*;type=alias;actions=update")
	TestRoleGrant(t, conn, roleDescendants.PublicId, "ids=*;type=*;actions=update")
	TestRoleGrant(t, conn, roleThisAndChildren.PublicId, "ids=*;type=account;actions=create,update")
	TestRoleGrant(t, conn, roleThisAndChildren.PublicId, "ids=*;type=group;actions=read;output_fields=id")

	// Add users to created roles
	for _, role := range []*Role{roleThis, roleOrg1, roleThisAndOrg2, roleDescendants, roleThisAndChildren} {
		_, err := repo.AddPrincipalRoles(ctx, role.PublicId, role.Version, []string{user.PublicId})
		require.NoError(t, err)
	}

	testcases := []struct {
		name     string
		input    testInput
		output   []perms.GrantTuple
		errorMsg string
	}{
		{
			name: "alias resource should return alias and '*' grants",
			input: testInput{
				userId:   user.PublicId,
				resource: []resource.Type{resource.Alias},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            roleThis.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=*;actions=*",
				},
				{
					RoleId:            roleThisAndOrg2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=alias;actions=delete",
				},
				{
					RoleId:            roleThisAndOrg2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=alias;actions=read",
				},
				{
					RoleId:            roleThisAndOrg2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=alias;actions=update",
				},
			},
		},
		{
			name: "account resource should return account and '*' grants",
			input: testInput{
				userId:   user.PublicId,
				resource: []resource.Type{resource.Account},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            roleThis.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=*;actions=*",
				},
				{
					RoleId:            roleThisAndChildren.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=account;actions=create,update",
				},
			},
		},
		{
			name: "group resource should return group and '*' grants",
			input: testInput{
				userId:   user.PublicId,
				resource: []resource.Type{resource.Group},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            roleThis.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=*;actions=*",
				},
				{
					RoleId:            roleThisAndChildren.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GlobalPrefix,
					Grant:             "ids=*;type=group;actions=read;output_fields=id",
				},
			},
		},
		{
			name: "u_anon should return no grants",
			input: testInput{
				userId:   globals.AnonymousUserId,
				resource: []resource.Type{resource.Alias},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants",
			input: testInput{
				userId:   globals.AnyAuthenticatedUserId,
				resource: []resource.Type{resource.Alias},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "missing user id should return error",
			input: testInput{
				resource: []resource.Type{resource.Alias},
			},
			errorMsg: "missing user id",
		},
		{
			name: "missing resource type should return error",
			input: testInput{
				userId: user.PublicId,
			},
			errorMsg: "missing resource type",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.GrantsForUser(ctx, tc.input.userId, tc.input.resource, globals.GlobalPrefix)
			if tc.errorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, got, tc.output)
		})
	}
}

func TestGrantsForUserOrgResources(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	user := TestUser(t, repo, globals.GlobalPrefix)

	// Create scopes
	org1 := TestOrg(t, repo, WithSkipDefaultRoleCreation(true))
	org2 := TestOrg(t, repo, WithSkipDefaultRoleCreation(true))

	// Create & grant roles
	roles := make([]*Role, 0)

	globalRoleOrg1 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId}))
	globalRoleThisAndOrg2 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, org2.PublicId}))
	globalRoleDescendants := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeDescendants}))
	globalRoleThisAndChildren := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
	roles = append(roles, globalRoleOrg1, globalRoleThisAndOrg2, globalRoleDescendants, globalRoleThisAndChildren)

	TestRoleGrant(t, conn, globalRoleOrg1.PublicId, "ids=*;type=user;actions=create,update")
	TestRoleGrant(t, conn, globalRoleOrg1.PublicId, "ids=*;type=user;actions=delete,read")
	TestRoleGrant(t, conn, globalRoleOrg1.PublicId, "ids=*;type=policy;actions=list,read")
	TestRoleGrant(t, conn, globalRoleThisAndOrg2.PublicId, "ids=*;type=user;actions=*")
	TestRoleGrant(t, conn, globalRoleDescendants.PublicId, "ids=*;type=*;actions=update")
	TestRoleGrant(t, conn, globalRoleThisAndChildren.PublicId, "ids=*;type=user;actions=set-accounts")
	TestRoleGrant(t, conn, globalRoleThisAndChildren.PublicId, "ids=*;type=policy;actions=read;output_fields=id")

	org1RoleThis := TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
	org1RoleChildren := TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeChildren}))
	org2RoleThis := TestRole(t, conn, org2.PublicId)
	org2RoleThisAndChildren := TestRole(t, conn, org2.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
	roles = append(roles, org1RoleThis, org1RoleChildren, org2RoleThis, org2RoleThisAndChildren)

	TestRoleGrant(t, conn, org1RoleThis.PublicId, "ids=*;type=*;actions=*")
	TestRoleGrant(t, conn, org1RoleChildren.PublicId, "ids=*;type=user;actions=add-accounts")
	TestRoleGrant(t, conn, org2RoleThis.PublicId, "ids=*;type=user;actions=list-resolvable-aliases")
	TestRoleGrant(t, conn, org2RoleThis.PublicId, "ids=*;type=policy;actions=list,no-op")
	TestRoleGrant(t, conn, org2RoleThisAndChildren.PublicId, "ids=*;type=policy;actions=*")

	// Add users to created roles
	for _, role := range roles {
		_, err := repo.AddPrincipalRoles(ctx, role.PublicId, role.Version, []string{user.PublicId})
		require.NoError(t, err)
	}

	testcases := []struct {
		name     string
		input    testInput
		output   []perms.GrantTuple
		errorMsg string
	}{
		{
			name: "return grants for user resource at org1 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: org1.PublicId,
				resource:   []resource.Type{resource.User},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleOrg1.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      org1.PublicId,
					Grant:             "ids=*;type=user;actions=create,update",
				},
				{
					RoleId:            globalRoleOrg1.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      org1.PublicId,
					Grant:             "ids=*;type=user;actions=delete,read",
				},
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=update",
				},
				{
					RoleId:            globalRoleThisAndChildren.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             "ids=*;type=user;actions=set-accounts",
				},
				{
					RoleId:            org1RoleThis.PublicId,
					RoleScopeId:       org1.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      org1.PublicId,
					Grant:             "ids=*;type=*;actions=*",
				},
			},
		},
		{
			name: "return grants for user resource at org2 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: org2.PublicId,
				resource:   []resource.Type{resource.User},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleThisAndOrg2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      org2.PublicId,
					Grant:             "ids=*;type=user;actions=*",
				},
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=update",
				},
				{
					RoleId:            globalRoleThisAndChildren.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             "ids=*;type=user;actions=set-accounts",
				},
				{
					RoleId:            org2RoleThis.PublicId,
					RoleScopeId:       org2.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      org2.PublicId,
					Grant:             "ids=*;type=user;actions=list-resolvable-aliases",
				},
			},
		},
		{
			name: "return grants for policy resource at org1 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: org1.PublicId,
				resource:   []resource.Type{resource.Policy},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleOrg1.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      org1.PublicId,
					Grant:             "ids=*;type=policy;actions=list,read",
				},
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=update",
				},
				{
					RoleId:            globalRoleThisAndChildren.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             "ids=*;type=policy;actions=read;output_fields=id",
				},
				{
					RoleId:            org1RoleThis.PublicId,
					RoleScopeId:       org1.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      org1.PublicId,
					Grant:             "ids=*;type=*;actions=*",
				},
			},
		},
		{
			name: "return grants for policy resource at org2 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: org2.PublicId,
				resource:   []resource.Type{resource.Policy},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=update",
				},
				{
					RoleId:            globalRoleThisAndChildren.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             "ids=*;type=policy;actions=read;output_fields=id",
				},
				{
					RoleId:            org2RoleThis.PublicId,
					RoleScopeId:       org2.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      org2.PublicId,
					Grant:             "ids=*;type=policy;actions=list,no-op",
				},
				{
					RoleId:            org2RoleThisAndChildren.PublicId,
					RoleScopeId:       org2.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      org2.PublicId,
					Grant:             "ids=*;type=policy;actions=*",
				},
			},
		},
		{
			name: "u_anon should return no grants at org1 request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: org1.PublicId,
				resource:   []resource.Type{resource.User},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_anon should return no grants at org2 request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: org2.PublicId,
				resource:   []resource.Type{resource.User},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at org1 request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: org1.PublicId,
				resource:   []resource.Type{resource.User},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at org2 request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: org2.PublicId,
				resource:   []resource.Type{resource.User},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "missing user id should return error",
			input: testInput{
				resource:   []resource.Type{resource.User},
				reqScopeId: org1.PublicId,
			},
			errorMsg: "missing user id",
		},
		{
			name: "missing scope id should return error",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: "",
				resource:   []resource.Type{resource.User},
			},
			errorMsg: "missing request scope id",
		},
		{
			name: "missing resource type should return error",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: org1.PublicId,
			},
			errorMsg: "missing resource type",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.GrantsForUser(ctx, tc.input.userId, tc.input.resource, tc.input.reqScopeId)
			if tc.errorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, got, tc.output)
		})
	}
}

func TestGrantsForUserProjectResources(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	user := TestUser(t, repo, globals.GlobalPrefix)

	// Create scopes
	org1 := TestOrg(t, repo, WithSkipDefaultRoleCreation(true))
	org2 := TestOrg(t, repo, WithSkipDefaultRoleCreation(true))

	proj1a := TestProject(t, repo, org1.PublicId, WithSkipDefaultRoleCreation(true))
	proj1b := TestProject(t, repo, org1.PublicId, WithSkipDefaultRoleCreation(true))
	proj2 := TestProject(t, repo, org2.PublicId, WithSkipDefaultRoleCreation(true))

	// Create & grant roles
	roles := make([]*Role, 0)

	globalRoleDescendants := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeDescendants}))
	globalRoleThisAndProj1a := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, proj1a.PublicId}))
	globalRoleProj2 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{proj2.PublicId}))
	roles = append(roles, globalRoleProj2, globalRoleThisAndProj1a, globalRoleDescendants)

	TestRoleGrant(t, conn, globalRoleDescendants.PublicId, "ids=*;type=*;actions=read")
	TestRoleGrant(t, conn, globalRoleThisAndProj1a.PublicId, "ids=*;type=target;actions=set-credential-sources")
	TestRoleGrant(t, conn, globalRoleProj2.PublicId, "ids=*;type=scope;actions=list,read")
	TestRoleGrant(t, conn, globalRoleProj2.PublicId, "ids=*;type=scope;actions=destroy-key-version")
	TestRoleGrant(t, conn, globalRoleProj2.PublicId, "ids=*;type=scope;actions=rotate-keys")
	TestRoleGrant(t, conn, globalRoleProj2.PublicId, "ids=*;type=target;actions=create,update")

	org1RoleProj1b := TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{proj1b.PublicId}))
	org2RoleThisAndChildren := TestRole(t, conn, org2.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
	roles = append(roles, org1RoleProj1b, org2RoleThisAndChildren)

	TestRoleGrant(t, conn, org1RoleProj1b.PublicId, "ids=*;type=target;actions=list-resolvable-aliases")
	TestRoleGrant(t, conn, org1RoleProj1b.PublicId, "ids=*;type=scope;actions=list,no-op")
	TestRoleGrant(t, conn, org2RoleThisAndChildren.PublicId, "ids=*;type=scope;actions=list-keys,read")

	proj1bRoleThis := TestRole(t, conn, proj1b.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
	proj2RoleThis := TestRole(t, conn, proj2.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
	roles = append(roles, proj1bRoleThis, proj2RoleThis)

	TestRoleGrant(t, conn, proj1bRoleThis.PublicId, "ids=*;type=*;actions=*")
	TestRoleGrant(t, conn, proj2RoleThis.PublicId, "ids=tssh_12345;actions=add-host-sources,remove-host-sources")
	TestRoleGrant(t, conn, proj2RoleThis.PublicId, "ids=*;type=scope;actions=attach-storage-policy,detach-storage-policy")

	// Add users to created roles
	for _, role := range roles {
		_, err := repo.AddPrincipalRoles(ctx, role.PublicId, role.Version, []string{user.PublicId})
		require.NoError(t, err)
	}

	testcases := []struct {
		name     string
		input    testInput
		output   []perms.GrantTuple
		errorMsg string
	}{
		{
			name: "return grants for target resource at proj1a request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj1a.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=read",
				},
				{
					RoleId:            globalRoleThisAndProj1a.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      proj1a.PublicId,
					Grant:             "ids=*;type=target;actions=set-credential-sources",
				},
			},
		},
		{
			name: "return grants for target resource at proj1b request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj1b.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=read",
				},
				{
					RoleId:            org1RoleProj1b.PublicId,
					RoleScopeId:       org1.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      proj1b.PublicId,
					Grant:             "ids=*;type=target;actions=list-resolvable-aliases",
				},
				{
					RoleId:            proj1bRoleThis.PublicId,
					RoleScopeId:       proj1b.PublicId,
					RoleParentScopeId: org1.PublicId,
					GrantScopeId:      proj1b.PublicId,
					Grant:             "ids=*;type=*;actions=*",
				},
			},
		},
		{
			name: "return grants for target resource at proj2 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj2.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=read",
				},
				{
					RoleId:            globalRoleProj2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      proj2.PublicId,
					Grant:             "ids=*;type=target;actions=create,update",
				},
				{
					RoleId:            proj2RoleThis.PublicId,
					RoleScopeId:       proj2.PublicId,
					RoleParentScopeId: org2.PublicId,
					GrantScopeId:      proj2.PublicId,
					Grant:             "ids=tssh_12345;actions=add-host-sources,remove-host-sources",
				},
			},
		},
		{
			name: "return grants for scope resource at proj1a request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj1a.PublicId,
				resource:   []resource.Type{resource.Scope},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=read",
				},
			},
		},
		{
			name: "return grants for scope resource at proj1b request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj1b.PublicId,
				resource:   []resource.Type{resource.Scope},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=read",
				},
				{
					RoleId:            org1RoleProj1b.PublicId,
					RoleScopeId:       org1.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      proj1b.PublicId,
					Grant:             "ids=*;type=scope;actions=list,no-op",
				},
				{
					RoleId:            proj1bRoleThis.PublicId,
					RoleScopeId:       proj1b.PublicId,
					RoleParentScopeId: org1.PublicId,
					GrantScopeId:      proj1b.PublicId,
					Grant:             "ids=*;type=*;actions=*",
				},
			},
		},
		{
			name: "return grants for scope resource at proj2 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj2.PublicId,
				resource:   []resource.Type{resource.Scope},
			},
			output: []perms.GrantTuple{
				{
					RoleId:            globalRoleDescendants.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Grant:             "ids=*;type=*;actions=read",
				},
				{
					RoleId:            globalRoleProj2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      proj2.PublicId,
					Grant:             "ids=*;type=scope;actions=list,read",
				},
				{
					RoleId:            globalRoleProj2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      proj2.PublicId,
					Grant:             "ids=*;type=scope;actions=destroy-key-version",
				},
				{
					RoleId:            globalRoleProj2.PublicId,
					RoleScopeId:       globals.GlobalPrefix,
					RoleParentScopeId: "",
					GrantScopeId:      proj2.PublicId,
					Grant:             "ids=*;type=scope;actions=rotate-keys",
				},
				{
					RoleId:            org2RoleThisAndChildren.PublicId,
					RoleScopeId:       org2.PublicId,
					RoleParentScopeId: globals.GlobalPrefix,
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             "ids=*;type=scope;actions=list-keys,read",
				},
				{
					RoleId:            proj2RoleThis.PublicId,
					RoleScopeId:       proj2.PublicId,
					RoleParentScopeId: org2.PublicId,
					GrantScopeId:      proj2.PublicId,
					Grant:             "ids=*;type=scope;actions=attach-storage-policy,detach-storage-policy",
				},
				{
					RoleId:            proj2RoleThis.PublicId,
					RoleScopeId:       proj2.PublicId,
					RoleParentScopeId: org2.PublicId,
					GrantScopeId:      proj2.PublicId,
					Grant:             "ids=tssh_12345;actions=add-host-sources,remove-host-sources",
				},
			},
		},
		{
			name: "u_anon should return no grants at proj1a request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: proj1a.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_anon should return no grants at proj1b request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: proj1b.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_anon should return no grants at proj2 request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: proj2.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at proj1a request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: proj1a.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at proj1b request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: proj1b.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at proj2 request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: proj2.PublicId,
				resource:   []resource.Type{resource.Target},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "missing user id should return error",
			input: testInput{
				resource:   []resource.Type{resource.Target},
				reqScopeId: proj2.PublicId,
			},
			errorMsg: "missing user id",
		},
		{
			name: "missing scope id should return error",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: "",
				resource:   []resource.Type{resource.Target},
			},
			errorMsg: "missing request scope id",
		},
		{
			name: "missing resource type should return error",
			input: testInput{
				reqScopeId: proj1a.PublicId,
				userId:     user.PublicId,
			},
			errorMsg: "missing resource type",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.GrantsForUser(ctx, tc.input.userId, tc.input.resource, tc.input.reqScopeId)
			if tc.errorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, got, tc.output)
		})
	}
}

func TestGrantsForUserRecursive(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	user := TestUser(t, repo, globals.GlobalPrefix)

	// Create scopes
	org1 := TestOrg(t, repo, WithSkipDefaultRoleCreation(true))
	org2 := TestOrg(t, repo, WithSkipDefaultRoleCreation(true))
	proj1a := TestProject(t, repo, org1.PublicId, WithSkipDefaultRoleCreation(true))
	proj1b := TestProject(t, repo, org1.PublicId, WithSkipDefaultRoleCreation(true))
	proj2 := TestProject(t, repo, org2.PublicId, WithSkipDefaultRoleCreation(true))

	// Create & grant roles
	roles := make([]*Role, 0)

	globalRoleThis := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis}))
	globalRoleChildren := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeChildren}))
	globalRoleThisAndDescendants := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeDescendants}))
	globalRoleOrg1AndProj2 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId, proj2.PublicId}))
	globalRoleOrg2 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org2.PublicId}))
	globalRoleProj1a := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{proj1a.PublicId}))
	globalRoleThisAndProj2 := TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, proj2.PublicId}))
	roles = append(roles, globalRoleThis, globalRoleChildren, globalRoleThisAndDescendants, globalRoleOrg1AndProj2, globalRoleOrg2, globalRoleProj1a, globalRoleThisAndProj2)

	TestRoleGrant(t, conn, globalRoleThis.PublicId, "ids=*;type=group;actions=create,update")
	TestRoleGrant(t, conn, globalRoleChildren.PublicId, "ids=*;type=group;actions=set-members")
	TestRoleGrant(t, conn, globalRoleThisAndDescendants.PublicId, "ids=*;type=*;actions=update")
	TestRoleGrant(t, conn, globalRoleOrg1AndProj2.PublicId, "ids=*;type=group;actions=list,read")
	TestRoleGrant(t, conn, globalRoleOrg2.PublicId, "ids=g_12345;actions=read")
	TestRoleGrant(t, conn, globalRoleProj1a.PublicId, "ids=*;type=group;actions=create,delete,read")
	TestRoleGrant(t, conn, globalRoleThisAndProj2.PublicId, "ids=g_12345,g_67890;actions=delete")

	org1RoleThis := TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
	org1RoleChildren := TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeChildren}))
	org2RoleThisAndChildren := TestRole(t, conn, org2.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
	org1RoleProj1b := TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{proj1b.PublicId}))
	org2RoleProj2 := TestRole(t, conn, org2.PublicId, WithGrantScopeIds([]string{proj2.PublicId}))
	roles = append(roles, org1RoleThis, org1RoleChildren, org1RoleProj1b, org2RoleThisAndChildren, org2RoleProj2)

	TestRoleGrant(t, conn, org1RoleThis.PublicId, "ids=g_67890;actions=read")
	TestRoleGrant(t, conn, org1RoleChildren.PublicId, "ids=*;type=group;actions=read,set-members")
	TestRoleGrant(t, conn, org2RoleThisAndChildren.PublicId, "ids=*;type=group;actions=delete")
	TestRoleGrant(t, conn, org1RoleProj1b.PublicId, "ids=*;type=group;actions=*")
	TestRoleGrant(t, conn, org2RoleProj2.PublicId, "ids=*;type=group;actions=read")

	proj1bRoleThis := TestRole(t, conn, proj1b.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
	proj2RoleThis := TestRole(t, conn, proj2.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
	roles = append(roles, proj1bRoleThis, proj2RoleThis)

	TestRoleGrant(t, conn, proj1bRoleThis.PublicId, "ids=*;type=*;actions=*")
	TestRoleGrant(t, conn, proj2RoleThis.PublicId, "ids=g_12345;actions=add-members,remove-members")
	TestRoleGrant(t, conn, proj2RoleThis.PublicId, "ids=*;type=group;actions=set-members")

	// Add user to created roles (some containing the list action)
	for _, role := range roles {
		_, err := repo.AddPrincipalRoles(ctx, role.PublicId, role.Version, []string{user.PublicId})
		require.NoError(t, err)
	}

	// If there's a list permission anywhere in the scope tree, the user should be able to perform recursive list at the global scope
	listResultSet := []perms.GrantTuple{
		{
			RoleId:            globalRoleOrg1AndProj2.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      org1.PublicId,
			Grant:             "ids=*;type=group;actions=list,read",
		},
		{
			RoleId:            globalRoleThisAndProj2.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      globals.GlobalPrefix,
			Grant:             "ids=g_12345,g_67890;actions=delete",
		},
		{
			RoleId:            globalRoleOrg2.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      org2.PublicId,
			Grant:             "ids=g_12345;actions=read",
		},
		{
			RoleId:            globalRoleProj1a.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      proj1a.PublicId,
			Grant:             "ids=*;type=group;actions=create,delete,read",
		},
		{
			RoleId:            globalRoleThisAndDescendants.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      globals.GlobalPrefix,
			Grant:             "ids=*;type=*;actions=update",
		},
		{
			RoleId:            org1RoleThis.PublicId,
			RoleScopeId:       org1.PublicId,
			RoleParentScopeId: globals.GlobalPrefix,
			GrantScopeId:      org1.PublicId,
			Grant:             "ids=g_67890;actions=read",
		},
		{
			RoleId:            org2RoleThisAndChildren.PublicId,
			RoleScopeId:       org2.PublicId,
			RoleParentScopeId: globals.GlobalPrefix,
			GrantScopeId:      org2.PublicId,
			Grant:             "ids=*;type=group;actions=delete",
		},
		{
			RoleId:            globalRoleChildren.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      "children",
			Grant:             "ids=*;type=group;actions=set-members",
		},
		{
			RoleId:            globalRoleThis.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      globals.GlobalPrefix,
			Grant:             "ids=*;type=group;actions=create,update",
		},
		{
			RoleId:            proj1bRoleThis.PublicId,
			RoleScopeId:       proj1b.PublicId,
			RoleParentScopeId: org1.PublicId,
			GrantScopeId:      proj1b.PublicId,
			Grant:             "ids=*;type=*;actions=*",
		},
		{
			RoleId:            org1RoleChildren.PublicId,
			RoleScopeId:       org1.PublicId,
			RoleParentScopeId: globals.GlobalPrefix,
			GrantScopeId:      "children",
			Grant:             "ids=*;type=group;actions=read,set-members",
		},
		{
			RoleId:            org1RoleProj1b.PublicId,
			RoleScopeId:       org1.PublicId,
			RoleParentScopeId: globals.GlobalPrefix,
			GrantScopeId:      proj1b.PublicId,
			Grant:             "ids=*;type=group;actions=*",
		},
		{
			RoleId:            globalRoleThisAndDescendants.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      globals.GrantScopeDescendants,
			Grant:             "ids=*;type=*;actions=update",
		},
		{
			RoleId:            globalRoleOrg1AndProj2.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      proj2.PublicId,
			Grant:             "ids=*;type=group;actions=list,read",
		},
		{
			RoleId:            globalRoleThisAndProj2.PublicId,
			RoleScopeId:       globals.GlobalPrefix,
			RoleParentScopeId: "",
			GrantScopeId:      proj2.PublicId,
			Grant:             "ids=g_12345,g_67890;actions=delete",
		},
		{
			RoleId:            org2RoleThisAndChildren.PublicId,
			RoleScopeId:       org2.PublicId,
			RoleParentScopeId: globals.GlobalPrefix,
			GrantScopeId:      globals.GrantScopeChildren,
			Grant:             "ids=*;type=group;actions=delete",
		},
		{
			RoleId:            org2RoleProj2.PublicId,
			RoleScopeId:       org2.PublicId,
			RoleParentScopeId: globals.GlobalPrefix,
			GrantScopeId:      proj2.PublicId,
			Grant:             "ids=*;type=group;actions=read",
		},
		{
			RoleId:            proj2RoleThis.PublicId,
			RoleScopeId:       proj2.PublicId,
			RoleParentScopeId: org2.PublicId,
			GrantScopeId:      proj2.PublicId,
			Grant:             "ids=g_12345;actions=add-members,remove-members",
		},
		{
			RoleId:            proj2RoleThis.PublicId,
			RoleScopeId:       proj2.PublicId,
			RoleParentScopeId: org2.PublicId,
			GrantScopeId:      proj2.PublicId,
			Grant:             "ids=*;type=group;actions=set-members",
		},
	}

	testcases := []struct {
		name     string
		input    testInput
		output   []perms.GrantTuple
		errorMsg string
	}{
		{
			name: "return grants for group resource at global request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Group},
			},
			output: listResultSet,
		},
		{
			name: "return grants for group resource at org1 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: org1.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: listResultSet,
		},
		{
			name: "return grants for group resource at org2 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: org2.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: listResultSet,
		},
		{
			name: "return grants for group resource at proj1a request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj1a.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: listResultSet,
		},
		{
			name: "return grants for group resource at proj1b request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj1b.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: listResultSet,
		},
		{
			name: "return grants for group resource at proj2 request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: proj2.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: listResultSet,
		},
		{
			name: "return error when trying to recursively list grants at an unknown request scope",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: scope.Unknown.String(),
				resource:   []resource.Type{resource.Group},
			},
			errorMsg: "request scope must be global scope, an org scope, or a project scope",
		},
		{
			name: "return no grants for a resource that has no permissions granted for it",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Role},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "unknown resource type should return error",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Unknown},
			},
			errorMsg: "resource type cannot be unknown",
		},
		{
			name: "'*' resource type should return error",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: globals.GlobalPrefix,
				resource:   []resource.Type{resource.All},
			},
			errorMsg: "resource type cannot be all",
		},
		{
			name: "u_anon should return no grants at global request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Group},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_anon should return no grants at org1 request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: org1.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_anon should return no grants at org2 request scope",
			input: testInput{
				userId:     globals.AnonymousUserId,
				reqScopeId: org2.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at global request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Group},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at org1 request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: org1.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "u_auth should return no grants at org2 request scope",
			input: testInput{
				userId:     globals.AnyAuthenticatedUserId,
				reqScopeId: org2.PublicId,
				resource:   []resource.Type{resource.Group},
			},
			output: []perms.GrantTuple{},
		},
		{
			name: "missing user id should return error",
			input: testInput{
				resource:   []resource.Type{resource.Group},
				reqScopeId: globals.GlobalPrefix,
			},
			errorMsg: "missing user id",
		},
		{
			name: "missing scope id should return error",
			input: testInput{
				userId:     user.PublicId,
				reqScopeId: "",
				resource:   []resource.Type{resource.Group},
			},
			errorMsg: "missing request scope id",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.GrantsForUser(ctx, tc.input.userId, tc.input.resource, tc.input.reqScopeId, WithRecursive(true))
			if tc.errorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, got, tc.output)
		})
	}
}
