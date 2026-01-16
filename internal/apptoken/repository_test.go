// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
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
	gToken := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, "individual")
	orgToken := TestAppToken(t, repo, org1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, "individual")
	projToken := TestAppToken(t, repo, proj1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, "individual")

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
	gToken := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, "individual")
	orgToken := TestAppToken(t, repo, org1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, "individual")
	projToken := TestAppToken(t, repo, proj1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, orgUser, true, "individual")

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
