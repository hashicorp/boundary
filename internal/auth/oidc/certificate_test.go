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

func TestCertificate_Create(t *testing.T) {
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

	_, pem := testGenerateCA(t, "localhost")
	type args struct {
		authMethodId string
		certificate  string
	}
	tests := []struct {
		name            string
		args            args
		want            *Certificate
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
				certificate:  pem,
			},
			create: true,
			want: func() *Certificate {
				want, err := NewCertificate(ctx, testAuthMethod.PublicId, pem)
				require.NoError(t, err)
				return want
			}(),
		},
		{
			name: "dup",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				certificate:  pem,
			},
			create: true,
			want: func() *Certificate {
				want, err := NewCertificate(ctx, testAuthMethod.PublicId, pem)
				require.NoError(t, err)
				return want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				certificate:  pem,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-certificate",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				certificate:  "",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewCertificate(ctx, tt.args.authMethodId, tt.args.certificate)
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
				found := AllocCertificate()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and certificate = ?", []any{tt.args.authMethodId, tt.args.certificate}))
				assert.Equal(got, &found)
			}
		})
	}
}

func TestCertificate_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	cert, _ := testGenerateCA(t, "localhost")

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name", WithApiUrl(TestConvertToUrls(t, "https://apiurl.com")[0]), WithCertificates(cert)) // seed an extra callback url to just make sure the delete only gets the right num of rows

	// make another test cert
	_, pem2 := testGenerateCA(t, "localhost")
	_, pem3 := testGenerateCA(t, "localhost")
	_, pem4 := testGenerateCA(t, "localhost")

	testResource := func(authMethodId string, cert string) *Certificate {
		c, err := NewCertificate(ctx, authMethodId, cert)
		require.NoError(t, err)
		return c
	}
	tests := []struct {
		name            string
		Certificate     *Certificate
		wantRowsDeleted int
		overrides       func(*Certificate)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			Certificate:     testResource(testAuthMethod.PublicId, pem2),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-OidcMethodId",
			Certificate:     testResource(testAuthMethod.PublicId, pem3),
			overrides:       func(c *Certificate) { c.OidcMethodId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "bad-pem",
			Certificate:     testResource(testAuthMethod.PublicId, pem4),
			overrides:       func(c *Certificate) { c.Cert = "bad-pem" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.Certificate.Clone()
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
			found := AllocCertificate()
			err = rw.LookupWhere(ctx, &found, "oidc_method_id = ? and certificate = ?", []any{tt.Certificate.OidcMethodId, tt.Certificate.Cert})
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestCertificate_Clone(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, pem := testGenerateCA(t, "localhost")
	_, pem2 := testGenerateCA(t, "127.0.0.1")

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewCertificate(ctx, m.PublicId, pem)
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.Certificate, orig.Certificate))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewCertificate(ctx, m.PublicId, pem)
		require.NoError(err)
		orig2, err := NewCertificate(ctx, m.PublicId, pem2)
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.Certificate, orig2.Certificate))
	})
}

func TestCertificate_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultCertificateTableName
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
			def := AllocCertificate()
			require.Equal(defaultTableName, def.TableName())
			m := AllocCertificate()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
