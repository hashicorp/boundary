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

func TestAccountClaimMap_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

	type args struct {
		authMethodId string
		to           AccountToClaim
		from         string
	}
	tests := []struct {
		name            string
		args            args
		want            *AccountClaimMap
		wantErr         bool
		wantIsErr       errors.Code
		create          bool
		wantCreateErr   bool
		wantCreateIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				to:           ToSubClaim,
				from:         "oid",
			},
			create: true,
			want: func() *AccountClaimMap {
				want := AllocAccountClaimMap()
				want.OidcMethodId = testAuthMethod.PublicId
				want.ToClaim = string(ToSubClaim)
				want.FromClaim = "oid"
				return &want
			}(),
		},
		{
			name: "dup", // must follow "valid" test. Url must be be unique for an OidcMethodId
			args: args{
				authMethodId: testAuthMethod.PublicId,
				to:           ToSubClaim,
				from:         "oid",
			},
			create: true,
			want: func() *AccountClaimMap {
				want := AllocAccountClaimMap()
				want.OidcMethodId = testAuthMethod.PublicId
				want.ToClaim = string(ToSubClaim)
				want.FromClaim = "oid"
				return &want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				to:           ToSubClaim,
				from:         "oid",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-to",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				from:         "oid",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-from",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				to:           ToSubClaim,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAccountClaimMap(context.TODO(), tt.args.authMethodId, tt.args.from, tt.args.to)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				ctx := context.Background()
				err = rw.Create(ctx, got)
				if tt.wantCreateErr {
					assert.Error(err)
					assert.True(errors.Match(errors.T(tt.wantCreateIsErr), err))
					return
				} else {
					assert.NoError(err)
				}
				found := AllocAccountClaimMap()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and to_claim = ?", []any{tt.args.authMethodId, tt.args.to}))
				assert.Equal(got, &found)
			}
		})
	}
}

func TestAccountClaimMap_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithAudClaims("alice.com")) // seed an extra callback url to just make sure the delete only gets the right num of rows

	testResource := func(authMethodId string, fromClaim string, toClaim AccountToClaim) *AccountClaimMap {
		c, err := NewAccountClaimMap(context.TODO(), authMethodId, fromClaim, toClaim)
		require.NoError(t, err)
		return c
	}
	tests := []struct {
		name            string
		AccountClaimMap *AccountClaimMap
		wantRowsDeleted int
		overrides       func(*AccountClaimMap)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			AccountClaimMap: testResource(testAuthMethod.PublicId, "oid", "sub"),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-OidcMethodId",
			AccountClaimMap: testResource(testAuthMethod.PublicId, "oid", "sub"),
			overrides:       func(c *AccountClaimMap) { c.OidcMethodId = "bad-id"; c.ToClaim = "sub" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "bad-toClaim",
			AccountClaimMap: testResource(testAuthMethod.PublicId, "oid", "sub"),
			overrides:       func(c *AccountClaimMap) { c.ToClaim = "bad-aud" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()

			_, err := rw.Exec(ctx, "delete from auth_oidc_account_claim_map", nil)
			require.NoError(err)

			cp := tt.AccountClaimMap.Clone()
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
			found := AllocAccountClaimMap()
			err = rw.LookupWhere(ctx, &found, "oidc_method_id = ? and to_claim = ?", []any{tt.AccountClaimMap.OidcMethodId, tt.AccountClaimMap.ToClaim})
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestAccountClaimMap_Clone(t *testing.T) {
	t.Parallel()
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
		orig, err := NewAccountClaimMap(context.TODO(), m.PublicId, "oid", ToSubClaim)
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.AccountClaimMap, orig.AccountClaimMap))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewAccountClaimMap(context.TODO(), m.PublicId, "oid", ToSubClaim)
		require.NoError(err)
		orig2, err := NewAccountClaimMap(context.TODO(), m.PublicId, "uid", ToSubClaim)
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.AccountClaimMap, orig2.AccountClaimMap))
	})
}

func TestAccountClaimMap_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultAcctClaimMapTableName
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
			def := AllocAccountClaimMap()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAccountClaimMap()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
