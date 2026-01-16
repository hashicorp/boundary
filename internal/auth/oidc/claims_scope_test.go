// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestClaimsScope_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

	type args struct {
		authMethodId string
		claimsScope  string
	}
	tests := []struct {
		name               string
		args               args
		createResource     bool
		createWantErrMatch *errors.Template
		want               *ClaimsScope
		wantErrMatch       *errors.Template
	}{
		{
			name: "valid",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				claimsScope:  "profile",
			},
			createResource: true,
			want: func() *ClaimsScope {
				want := AllocClaimsScope()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Scope = "profile"
				return &want
			}(),
		},
		{
			name: "dup",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				claimsScope:  "profile",
			},
			createResource: true,
			want: func() *ClaimsScope {
				want := AllocClaimsScope()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Scope = "profile"
				return &want
			}(),
			createWantErrMatch: errors.T(errors.NotUnique),
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				claimsScope:  "empty-auth-method",
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "empty-aud",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				claimsScope:  "",
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "openid-default-error",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				claimsScope:  DefaultClaimsScope,
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewClaimsScope(ctx, tt.args.authMethodId, tt.args.claimsScope)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted error %s and got: %s", tt.wantErrMatch.Code, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.createResource {
				err := rw.Create(ctx, got)
				if tt.createWantErrMatch != nil {
					require.Error(err)
					assert.Truef(errors.Match(tt.createWantErrMatch, err), "wanted error %s and got: %s", tt.createWantErrMatch.Code, err.Error())
					return
				}
				assert.NoError(err)
				found := AllocClaimsScope()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and scope = ?", []any{tt.args.authMethodId, tt.args.claimsScope}))
			}
		})
	}
}

func TestClaimsScope_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithAudClaims("alice.com")) // seed an extra callback url to just make sure the delete only gets the right num of rows

	testResource := func(authMethodId string, claimsScope string) *ClaimsScope {
		c, err := NewClaimsScope(ctx, authMethodId, claimsScope)
		require.NoError(t, err)
		return c
	}
	tests := []struct {
		name            string
		claimsScope     *ClaimsScope
		wantRowsDeleted int
		overrides       func(*ClaimsScope)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			claimsScope:     testResource(testAuthMethod.PublicId, "email"),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-OidcMethodId",
			claimsScope:     testResource(testAuthMethod.PublicId, "email"),
			overrides:       func(c *ClaimsScope) { c.OidcMethodId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "bad-scope",
			claimsScope:     testResource(testAuthMethod.PublicId, "valid-3"),
			overrides:       func(c *ClaimsScope) { c.Scope = "bad-scope" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.claimsScope.Clone()
			require.NoError(rw.Create(ctx, &cp))

			if tt.overrides != nil {
				tt.overrides(cp)
			}
			deletedRows, err := rw.Delete(ctx, &cp)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found := AllocClaimsScope()
			err = rw.LookupWhere(ctx, &found, "oidc_method_id = ? and scope = ?", []any{tt.claimsScope.OidcMethodId, tt.claimsScope.Scope})
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestClaimsScope_Clone(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewClaimsScope(ctx, m.PublicId, "profile")
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.ClaimsScope, orig.ClaimsScope))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewClaimsScope(ctx, m.PublicId, "email")
		require.NoError(err)
		orig2, err := NewClaimsScope(ctx, m.PublicId, "profile")
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.ClaimsScope, orig2.ClaimsScope))
	})
}

func TestClaimsScope_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultClaimsScopeTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocClaimsScope()
			require.Equal(defaultTableName, def.TableName())
			m := AllocClaimsScope()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
