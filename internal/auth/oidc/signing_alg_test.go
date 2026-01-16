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

func TestSigningAlg_Create(t *testing.T) {
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
		alg          Alg
	}
	tests := []struct {
		name            string
		args            args
		want            *SigningAlg
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
				alg:          RS256,
			},
			create: true,
			want: func() *SigningAlg {
				want := AllocSigningAlg()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Alg = string(RS256)
				return &want
			}(),
		},
		{
			name: "dup", // must follow "valid" test. Alg must be be unique for an OidcMethodId
			args: args{
				authMethodId: testAuthMethod.PublicId,
				alg:          RS256,
			},
			create: true,
			want: func() *SigningAlg {
				want := AllocSigningAlg()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Alg = string(RS256)
				return &want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				alg:          RS256,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-alg",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				alg:          "",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "supported-alg",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				alg:          Alg("EVE256"), // The unsupported evesdropper 256 curve
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewSigningAlg(ctx, tt.args.authMethodId, tt.args.alg)
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
				found := AllocSigningAlg()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and signing_alg_name = ?", []any{tt.args.authMethodId, string(tt.args.alg)}))
				assert.Equal(got, &found)
			}
		})
	}
}

func TestSigningAlg_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(
		t,
		conn,
		databaseWrapper,
		org.PublicId,
		InactiveState,
		"alice_rp",
		"my-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]),
		WithSigningAlgs(RS256)) // seed an extra callback url to just make sure the delete only gets the right num of rows

	testResource := func(authMethodId string, signingAlg Alg) *SigningAlg {
		c, err := NewSigningAlg(ctx, authMethodId, signingAlg)
		require.NoError(t, err)
		return c
	}
	tests := []struct {
		name            string
		SigningAlg      *SigningAlg
		wantRowsDeleted int
		overrides       func(*SigningAlg)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			SigningAlg:      testResource(testAuthMethod.PublicId, RS384),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-OidcMethodId",
			SigningAlg:      testResource(testAuthMethod.PublicId, RS512),
			overrides:       func(c *SigningAlg) { c.OidcMethodId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "bad-Url",
			SigningAlg:      testResource(testAuthMethod.PublicId, ES256),
			overrides:       func(c *SigningAlg) { c.Alg = "bad-alg" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.SigningAlg.Clone()
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
			found := AllocSigningAlg()
			err = rw.LookupWhere(ctx, &found, "oidc_method_id = ? and signing_alg_name = ?", []any{tt.SigningAlg.OidcMethodId, tt.SigningAlg.String()})
			assert.Truef(errors.IsNotFoundError(err), "unexpected error: %s", err.Error())
		})
	}
}

func TestSigningAlg_Clone(t *testing.T) {
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
		orig, err := NewSigningAlg(ctx, m.PublicId, RS256)
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.SigningAlg, orig.SigningAlg))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewSigningAlg(ctx, m.PublicId, ES256)
		require.NoError(err)
		orig2, err := NewSigningAlg(ctx, m.PublicId, ES384)
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.SigningAlg, orig2.SigningAlg))
	})
}

func TestSigningAlg_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultSigningAlgTableName
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
			def := AllocSigningAlg()
			require.Equal(defaultTableName, def.TableName())
			m := AllocSigningAlg()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
