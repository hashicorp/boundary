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

func TestAudClaim_Create(t *testing.T) {
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
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

	type args struct {
		authMethodId string
		aud          string
	}
	tests := []struct {
		name            string
		args            args
		want            *AudClaim
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
				aud:          "valid",
			},
			create: true,
			want: func() *AudClaim {
				want := AllocAudClaim()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Aud = "valid"
				return &want
			}(),
		},
		{
			name: "dup", // must follow "valid" test. Url must be be unique for an OidcMethodId
			args: args{
				authMethodId: testAuthMethod.PublicId,
				aud:          "valid",
			},
			create: true,
			want: func() *AudClaim {
				want := AllocAudClaim()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Aud = "valid"
				return &want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				aud:          "empty-auth-method",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-aud",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				aud:          "",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAudClaim(ctx, tt.args.authMethodId, tt.args.aud)
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
				found := AllocAudClaim()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and aud_claim = ?", []any{tt.args.authMethodId, tt.args.aud}))
				assert.Equal(got, &found)
			}
		})
	}
}

func TestAudClaim_Delete(t *testing.T) {
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

	testResource := func(authMethodId string, AudClaim string) *AudClaim {
		c, err := NewAudClaim(ctx, authMethodId, AudClaim)
		require.NoError(t, err)
		return c
	}
	tests := []struct {
		name            string
		AudClaim        *AudClaim
		wantRowsDeleted int
		overrides       func(*AudClaim)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			AudClaim:        testResource(testAuthMethod.PublicId, "valid"),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-OidcMethodId",
			AudClaim:        testResource(testAuthMethod.PublicId, "valid-2"),
			overrides:       func(c *AudClaim) { c.OidcMethodId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "bad-aud",
			AudClaim:        testResource(testAuthMethod.PublicId, "valid-3"),
			overrides:       func(c *AudClaim) { c.Aud = "bad-aud" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.AudClaim.Clone()
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
			found := AllocAudClaim()
			err = rw.LookupWhere(ctx, &found, "oidc_method_id = ? and aud_claim = ?", []any{tt.AudClaim.OidcMethodId, tt.AudClaim.Aud})
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestAudClaim_Clone(t *testing.T) {
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
		orig, err := NewAudClaim(ctx, m.PublicId, "eve.com")
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.AudClaim, orig.AudClaim))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewAudClaim(ctx, m.PublicId, "eve.com")
		require.NoError(err)
		orig2, err := NewAudClaim(ctx, m.PublicId, "alice.com")
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.AudClaim, orig2.AudClaim))
	})
}

func TestAudClaim_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultAudClaimTableName
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
			def := AllocAudClaim()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAudClaim()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
