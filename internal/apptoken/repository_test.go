// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
	}

	tests := []struct {
		name          string
		args          args
		want          *Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
			},
			want: &Repository{
				reader: rw,
				writer: rw,
				kms:    testKms,
			},
			wantErr: false,
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "apptoken.NewRepository: nil kms: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "apptoken.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "apptoken.NewRepository: nil reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(t.Context(), tt.args.r, tt.args.w, tt.args.kms)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_CreateAppToken(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	u := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	org, proj := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)

	tests := []struct {
		at   *AppToken
		name string

		wantPerms []testPermission

		wantErr     bool
		wantErrMsg  string
		wantIsError errors.Code
	}{
		// global
		{
			name: "valid-global-basic-no-perms",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
			},
			wantErr: false,
		},
		{
			name: "valid-global-extensive-no-perms",
			at: &AppToken{
				ScopeId:            globals.GlobalPrefix,
				CreatedByUserId:    u.PublicId,
				Name:               "test-token",
				Description:        "a test token",
				Revoked:            false,
				TimeToStaleSeconds: 36000,
				ExpirationTime:     timestamp.New(timestamp.Now().AsTime().Add(1000 * time.Hour)),
			},
			wantErr: false,
		},
		{
			name: "invalid-global-same-name",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Name:            "test-token",
			},
			wantErr:    true,
			wantErrMsg: "duplicate key value violates unique constraint \"app_token_global_name_scope_id_uq\"",
		},
		{
			name: "valid-global-one-perm",
			at: &AppToken{
				ScopeId:            globals.GlobalPrefix,
				CreatedByUserId:    u.PublicId,
				Name:               "test-token-perms",
				Description:        "a test token",
				Revoked:            false,
				TimeToStaleSeconds: 36000,
				ExpirationTime:     timestamp.New(timestamp.Now().AsTime().Add(1000 * time.Hour)),
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{"this", "descendants"},
					},
				},
			},
			wantPerms: []testPermission{
				{
					GrantThis:   true,
					GrantScope:  "descendants",
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-global-two-perm",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{"this", "descendants"},
					},
					{
						Label:         "test-2",
						Grants:        []string{"type=target;actions=list"},
						GrantedScopes: []string{"children"},
					},
				},
			},
			wantErr: false,
			wantPerms: []testPermission{
				{
					GrantScope:  "descendants",
					GrantThis:   true,
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{},
				},
				{
					GrantScope:  "children",
					GrantThis:   false,
					Description: "test-2",
					Grants:      []string{"type=target;actions=list"},
					Scopes:      []string{},
				},
			},
		},
		{
			name: "valid-global-one-perm-specific-grantedscope",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{org.GetPublicId()},
					},
				},
			},
			wantPerms: []testPermission{
				{
					GrantThis:   false,
					GrantScope:  "individual",
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{org.GetPublicId()},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-global-one-perm-this-and-specific-grantedscope",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{"this", proj.GetPublicId()},
					},
				},
			},
			wantPerms: []testPermission{
				{
					GrantThis:   true,
					GrantScope:  "individual",
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{proj.GetPublicId()},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-global-multiple-mixed-perms",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list"},
						GrantedScopes: []string{proj.GetPublicId()},
					},
					{
						Label:         "test2",
						Grants:        []string{"type=target;actions=list"},
						GrantedScopes: []string{"this", proj.GetPublicId(), proj2.GetPublicId()},
					},
					{
						Label:         "test3",
						Grants:        []string{"type=session;actions=list"},
						GrantedScopes: []string{"this", proj2.GetPublicId(), "children"},
					},
					{
						Label:         "test4",
						Grants:        []string{"type=role;actions=list", "type=user;actions=list"},
						GrantedScopes: []string{"descendants"},
					},
					{
						Label:         "test5",
						Grants:        []string{"type=group;actions=list", "type=scope;actions=list"},
						GrantedScopes: []string{"this", org2.GetPublicId()},
					},
				},
			},
			wantPerms: []testPermission{
				{
					Description: "test",
					GrantScope:  "individual",
					GrantThis:   false,
					Grants:      []string{"type=host-catalog;actions=list"},
					Scopes:      []string{proj.GetPublicId()},
				},
				{
					Description: "test2",
					GrantScope:  "individual",
					GrantThis:   true,
					Grants:      []string{"type=target;actions=list"},
					Scopes:      []string{proj.GetPublicId(), proj2.GetPublicId()},
				},
				{
					Description: "test3",
					GrantScope:  "children",
					GrantThis:   true,
					Grants:      []string{"type=session;actions=list"},
					Scopes:      []string{proj2.GetPublicId()},
				},
				{
					Description: "test4",
					GrantScope:  "descendants",
					GrantThis:   false,
					Grants:      []string{"type=role;actions=list", "type=user;actions=list"},
					Scopes:      []string{},
				},
				{
					Description: "test5",
					GrantScope:  "individual",
					GrantThis:   true,
					Grants:      []string{"type=group;actions=list", "type=scope;actions=list"},
					Scopes:      []string{org2.GetPublicId()},
				},
			},
			wantErr: false,
		},
		// org
		{
			name: "valid-org-basic-no-perms",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
			},
			wantErr: false,
		},
		{
			name: "valid-org-one-perm",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{"this", "children"},
					},
				},
			},
			wantPerms: []testPermission{
				{
					GrantThis:   true,
					GrantScope:  "children",
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-org-two-perm",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{"this", "children"},
					},
					{
						Label:         "test-2",
						Grants:        []string{"type=target;actions=list"},
						GrantedScopes: []string{"children"},
					},
				},
			},
			wantErr: false,
			wantPerms: []testPermission{
				{
					GrantScope:  "children",
					GrantThis:   true,
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{},
				},
				{
					GrantScope:  "children",
					GrantThis:   false,
					Description: "test-2",
					Grants:      []string{"type=target;actions=list"},
					Scopes:      []string{},
				},
			},
		},
		{
			name: "valid-org-one-perm-specific-grantedscope",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{proj.GetPublicId()},
					},
				},
			},
			wantPerms: []testPermission{
				{
					GrantThis:   false,
					GrantScope:  "individual",
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{proj.GetPublicId()},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-org-one-perm-this-and-specific-grantedscope",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list", "type=session;actions=list"},
						GrantedScopes: []string{"this", proj.GetPublicId()},
					},
				},
			},
			wantPerms: []testPermission{
				{
					GrantThis:   true,
					GrantScope:  "individual",
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list", "type=session;actions=list"},
					Scopes:      []string{proj.GetPublicId()},
				},
			},
			wantErr: false,
		},
		{
			name: "valid-org-multiple-mixed-perms",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list"},
						GrantedScopes: []string{"children"},
					},
					{
						Label:         "test2",
						Grants:        []string{"type=target;actions=list"},
						GrantedScopes: []string{"this", proj.GetPublicId()},
					},
					{
						Label:         "test3",
						Grants:        []string{"type=session;actions=list", "type=role;actions=list"},
						GrantedScopes: []string{"this", "children"},
					},
				},
			},
			wantPerms: []testPermission{
				{
					GrantThis:   false,
					GrantScope:  "children",
					Description: "test",
					Grants:      []string{"type=host-catalog;actions=list"},
					Scopes:      []string{},
				},
				{
					GrantThis:   true,
					GrantScope:  "individual",
					Description: "test2",
					Grants:      []string{"type=target;actions=list"},
					Scopes:      []string{proj.GetPublicId()},
				},
				{
					GrantThis:   true,
					GrantScope:  "children",
					Description: "test3",
					Grants:      []string{"type=session;actions=list", "type=role;actions=list"},
					Scopes:      []string{},
				},
			},
			wantErr: false,
		},
		// invalid
		{
			name: "invalid-global-bad-grant",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"oops_broken", "type=session;actions=list"},
						GrantedScopes: []string{"this", "descendants"},
					},
				},
			},
			wantErr:    true,
			wantErrMsg: "parsing grant string",
		},
		{
			name: "invalid-global-bad-grantedscope",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=session;actions=list"},
						GrantedScopes: []string{"whoopsie"},
					},
				},
			},
			wantErr:    true,
			wantErrMsg: "invalid grant scope",
		},
		{
			name: "invalid-global-bad-grantedscope-mixing",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=session;actions=list"},
						GrantedScopes: []string{"children", "descendants"},
					},
				},
			},
			wantErr:     true,
			wantIsError: 100,
			wantErrMsg:  "only one of descendants or children grant scope can be specified",
		},
		{
			name: "invalid-org-not-child",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list"},
						GrantedScopes: []string{proj.GetPublicId()},
					},
					{
						Label:         "test2",
						Grants:        []string{"type=target;actions=list"},
						GrantedScopes: []string{"this", proj2.GetPublicId()},
					},
				},
			},
			wantErr:     true,
			wantIsError: errors.Exception,
			wantErrMsg:  "is not a child of org",
		},
		{
			name: "invalid-org-project-and-children",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list"},
						GrantedScopes: []string{proj.GetPublicId(), "children"},
					},
				},
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
			wantErrMsg:  "children grant scope cannot be combined with individual project grant scopes",
		},
		{
			name: "invalid-org-descendants",
			at: &AppToken{
				ScopeId:         org.PublicId,
				CreatedByUserId: u.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"type=host-catalog;actions=list"},
						GrantedScopes: []string{"descendants"},
					},
				},
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
			wantErrMsg:  "org cannot have descendants grant scope",
		},
		{
			name:        "nil-token",
			at:          nil,
			wantErr:     true,
			wantErrMsg:  "apptoken.(Repository).CreateToken: missing app token: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "bad-scope-id",
			at: &AppToken{
				ScopeId:         "bad-id",
				CreatedByUserId: u.PublicId,
			},
			wantErrMsg:  "apptoken.(Repository).CreateToken: invalid scope type: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
			wantErr:     true,
		},
		{
			name: "bad-user-id",
			at: &AppToken{
				ScopeId:         globals.GlobalPrefix,
				CreatedByUserId: "whomp",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			// validate app token
			at, err := repo.CreateAppToken(ctx, tt.at)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(at)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			assert.NoError(err)
			assert.NotNil(at.CreateTime)
			assert.NotNil(at.ApproximateLastAccessTime)
			assert.NotNil(at.Token)
			assert.Equal(at.CreateTime, at.ApproximateLastAccessTime)
			assert.GreaterOrEqual(at.ExpirationTime.AsTime().Unix(), at.CreateTime.AsTime().Unix())

			// validate app token permission global using db queries
			if tt.at.Permissions != nil {
				err = testCheckPermission(t, repo, at.PublicId, tt.at.ScopeId, tt.wantPerms)
				assert.NoError(err)
			}

			// validate app token cipher using db queries
			err = testCheckAppTokenCipher(t, repo, at.PublicId)
			assert.NoError(err)
		})
	}
}

func TestRepository_queryAppTokens(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)

	// Create test data
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithName("org1"), iam.WithDescription("Test Org 1"))
	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	orgUser := iam.TestUser(t, iamRepo, org1.PublicId)

	// Create app tokens
	gToken := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, globals.GrantScopeIndividual)
	orgToken := TestAppToken(t, repo, org1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, globals.GrantScopeIndividual)
	projToken := TestAppToken(t, repo, proj1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, globals.GrantScopeIndividual)

	testCases := []struct {
		name            string
		whereClause     string
		args            []any
		opts            []db.Option
		wantTokens      []*AppToken
		wantErr         bool
		wantErrContains string
	}{
		{
			name:        "valid query with global scope",
			whereClause: "scope_id = @scope_id",
			args:        []any{sql.Named("scope_id", gToken.ScopeId)},
			opts:        []db.Option{db.WithLimit(10)},
			wantTokens:  []*AppToken{gToken},
			wantErr:     false,
		},
		{
			name:        "valid query with order",
			whereClause: "scope_id = @scope_id",
			args:        []any{sql.Named("scope_id", gToken.ScopeId)},
			opts:        []db.Option{db.WithLimit(5), db.WithOrder("create_time desc")},
			wantTokens:  []*AppToken{gToken},
			wantErr:     false,
		},
		{
			name:        "valid query with multiple scopes",
			whereClause: "scope_id in @scope_ids",
			args:        []any{sql.Named("scope_ids", []string{gToken.ScopeId, orgToken.ScopeId})},
			opts:        []db.Option{db.WithLimit(10)},
			wantTokens:  []*AppToken{gToken, orgToken},
			wantErr:     false,
		},
		{
			name:        "valid query with all scopes",
			whereClause: "scope_id in @scope_ids",
			args:        []any{sql.Named("scope_ids", []string{gToken.ScopeId, orgToken.ScopeId, projToken.ScopeId})},
			opts:        []db.Option{db.WithLimit(10)},
			wantTokens:  []*AppToken{gToken, orgToken, projToken},
			wantErr:     false,
		},
		{
			name:        "empty results",
			whereClause: "scope_id = @scope_id",
			args:        []any{sql.Named("scope_id", "nonexistent_scope")},
			opts:        []db.Option{db.WithLimit(10)},
			wantTokens:  []*AppToken{},
			wantErr:     false,
		},
		{
			name:            "invalid where clause",
			whereClause:     "invalid_column = @value",
			args:            []any{sql.Named("scope_ids", []string{gToken.ScopeId, orgToken.ScopeId})},
			opts:            []db.Option{db.WithLimit(10)},
			wantTokens:      nil,
			wantErr:         true,
			wantErrContains: "column \"invalid_column\" does not exist",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)

			tokens, _, err := repo.queryAppTokens(ctx, tc.whereClause, tc.args, tc.opts...)
			if tc.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains)
				return
			}

			require.NoError(err)
			assert.Equal(len(tc.wantTokens), len(tokens))
			for i, wantToken := range tc.wantTokens {
				gotToken := tokens[i]
				assert.Equal(wantToken.PublicId, gotToken.PublicId)
				assert.Equal(wantToken.ScopeId, gotToken.ScopeId)
			}
		})
	}
}

func TestRepository_listAppTokens(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)

	// Create test data
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithName("org1"), iam.WithDescription("Test Org 1"))
	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	orgUser := iam.TestUser(t, iamRepo, org1.PublicId)

	// Create app tokens
	gToken := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, globals.GrantScopeIndividual)
	orgToken := TestAppToken(t, repo, org1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, globals.GrantScopeIndividual)
	projToken := TestAppToken(t, repo, proj1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, globals.GrantScopeIndividual)

	testCases := []struct {
		name           string
		withScopeIds   []string
		opts           []Option
		wantTokens     []*AppToken
		wantErr        bool
		wantErrMessage string
	}{
		{
			name:         "list with global scope",
			withScopeIds: []string{gToken.ScopeId},
			opts:         []Option{WithLimit(10)},
			wantTokens:   []*AppToken{gToken},
			wantErr:      false,
		},
		{
			name:         "list with org scope",
			withScopeIds: []string{orgToken.ScopeId},
			opts:         []Option{WithLimit(10)},
			wantTokens:   []*AppToken{orgToken},
			wantErr:      false,
		},
		{
			name:         "list with project scope",
			withScopeIds: []string{projToken.ScopeId},
			opts:         []Option{WithLimit(10)},
			wantTokens:   []*AppToken{projToken},
			wantErr:      false,
		},
		{
			name:         "list with all scopes",
			withScopeIds: []string{gToken.ScopeId, orgToken.ScopeId, projToken.ScopeId},
			opts:         []Option{WithLimit(10)},
			wantTokens:   []*AppToken{gToken, orgToken, projToken},
			wantErr:      false,
		},
		{
			name:         "list with no matching scopes",
			withScopeIds: []string{"nonexistent_scope"},
			opts:         []Option{WithLimit(10)},
			wantTokens:   []*AppToken{},
			wantErr:      false,
		},
		{
			name:           "list with empty scope ids",
			withScopeIds:   []string{},
			opts:           []Option{WithLimit(10)},
			wantTokens:     nil,
			wantErr:        true,
			wantErrMessage: "apptoken.(Repository).listAppTokens: missing scope id: parameter violation: error #100",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)

			tokens, _, err := repo.listAppTokens(ctx, tc.withScopeIds, tc.opts...)
			if tc.wantErr {
				require.Error(err)
				assert.Equal(tc.wantErrMessage, err.Error())
				return
			}

			require.NoError(err)
			assert.Equal(len(tc.wantTokens), len(tokens))

			// Verify that all expected tokens are present in the result
			// The order is not guaranteed, so we check presence rather than position
			for _, wantToken := range tc.wantTokens {
				found := false
				for _, gotToken := range tokens {
					if wantToken.PublicId == gotToken.PublicId && wantToken.ScopeId == gotToken.ScopeId {
						found = true
						break
					}
				}
				assert.True(found)
			}
		})
	}

	t.Run("list that exceeds limit", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)

		orgExceedLimit, _ := iam.TestScopes(t, iamRepo, iam.WithName("orgExceedLimit"), iam.WithDescription("Test Org Exceed Limit"))
		orgExceedLimitUser := iam.TestUser(t, iamRepo, orgExceedLimit.PublicId)

		// Create enough tokens to exceed the limit
		for range make([]int, 5) {
			TestAppToken(t, repo, orgExceedLimit.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgExceedLimitUser, true, "individual")
		}

		tokens, _, err := repo.listAppTokens(ctx, []string{orgExceedLimit.PublicId}, []Option{WithLimit(10)}...)
		require.NoError(err)
		assert.Equal(len(tokens), 5) // all 5 tokens returned

		tokens, _, err = repo.listAppTokens(ctx, []string{orgExceedLimit.PublicId}, []Option{WithLimit(4)}...)
		require.NoError(err)
		assert.Equal(len(tokens), 4) // limited to 4
	})
}
