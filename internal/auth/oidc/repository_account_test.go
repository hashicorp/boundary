// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	noIssuerAm := TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), InactiveState,
		"client", "fido",
		WithSigningAlgs(RS256),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	tests := []struct {
		name       string
		in         *Account
		opts       []Option
		want       *Account
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "nil-Account",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateAccount: missing Account: parameter violation: error #100",
		},
		{
			name:       "nil-embedded-Account",
			in:         &Account{},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateAccount: missing embedded Account: parameter violation: error #100",
		},
		{
			name: "invalid-no-auth-method-id",
			in: &Account{
				Account: &store.Account{},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateAccount: missing auth method id: parameter violation: error #100",
		},
		{
			name: "invalid-public-id-set",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					PublicId:     "hcst_OOOOOOOOOO",
					Subject:      "invalid public id set",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateAccount: public id must be empty: parameter violation: error #100",
		},
		{
			name: "invalid-no-subject",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateAccount: missing subject: parameter violation: error #100",
		},
		{
			name: "invalid-no-issuer-authmethod-no-issuer",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: noIssuerAm.PublicId,
					Subject:      "invalid no issuer authmethod no issuer",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateAccount: no issuer on auth method: parameter violation: error #100",
		},
		{
			name: "valid-provide-issuer-authmethod-no-issuer",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: noIssuerAm.PublicId,
					Subject:      "valid provide issuer authmethod no issuer",
					Issuer:       "https://overwrite.com",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Issuer:       "https://overwrite.com",
					Subject:      "valid provide issuer authmethod no issuer",
				},
			},
		},
		{
			name: "valid-no-options",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Subject:      "valid-no-options",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Issuer:       "https://www.alice.com",
					Subject:      "valid-no-options",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Subject:      "valid-with-name",
					Name:         "test-name-repo",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Issuer:       "https://www.alice.com",
					Subject:      "valid-with-name",
					Name:         "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Subject:      "valid-with-description",
					Description:  ("test-description-repo"),
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Issuer:       "https://www.alice.com",
					Subject:      "valid-with-description",
					Description:  ("test-description-repo"),
				},
			},
		},
		{
			name: "valid-overwrite-issuer",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Subject:      "valid-overwrite-issuer",
					Issuer:       "https://overwrite.com",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Issuer:       "https://overwrite.com",
					Subject:      "valid-overwrite-issuer",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.OidcAccountPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.Subject, got.Subject)
			assert.Equal(tt.want.Issuer, got.Issuer)
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_CreateAccount_DuplicateFields(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	ctx := context.Background()

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethod := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)

		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethod.GetPublicId(),
				Name:         "test-name-repo",
				Subject:      "subject",
			},
		}

		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.OidcAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-parents", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethoda := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp1", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		authMethodb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp2", "fido",
			WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
			WithSigningAlgs(RS256),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		in := &Account{
			Account: &store.Account{
				Name:    "test-name-repo",
				Subject: "subject1",
			},
		}
		in2 := in.Clone()

		in.AuthMethodId = authMethoda.GetPublicId()
		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.OidcAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.AuthMethodId = authMethodb.GetPublicId()
		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.OidcAccountPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})

	t.Run("invalid-duplicate-subjects", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethod := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)

		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethod.GetPublicId(),
				Subject:      "subject1",
			},
		}

		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.OidcAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-subject-diff-authmethod", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethoda := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp1", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		authMethodb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp2", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		in := &Account{
			Account: &store.Account{
				Subject: "subject1",
			},
		}
		in2 := in.Clone()

		in.AuthMethodId = authMethoda.GetPublicId()
		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.OidcAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(in.Subject, got.Subject)
		assert.Equal(authMethoda.GetIssuer(), got.Issuer)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.AuthMethodId = authMethodb.GetPublicId()
		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.OidcAccountPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(in2.Subject, got2.Subject)
		assert.Equal(authMethodb.GetIssuer(), got2.Issuer)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})

	t.Run("valid-duplicate-subject-diff-issuer", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethod := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp1", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethod.GetPublicId(),
				Subject:      "subject1",
			},
		}
		in2 := in.Clone()

		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.OidcAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(in.Subject, got.Subject)
		assert.Equal(authMethod.Issuer, got.Issuer)
		assert.Equal(got.CreateTime, got.UpdateTime)

		authMethod.Issuer = "https://somethingelse.com"
		authMethod, _, err = repo.UpdateAuthMethod(ctx, authMethod, authMethod.Version, []string{IssuerField}, WithForce())
		require.NoError(err)

		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.OidcAccountPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(in2.Subject, got2.Subject)
		assert.Equal(authMethod.Issuer, got2.Issuer)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_LookupAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	account := TestAccount(t, conn, authMethod, "test-subject")

	newAcctId, err := newAccountId(ctx, authMethod.GetPublicId(), authMethod.Issuer, "random-id")
	require.NoError(t, err)
	tests := []struct {
		name       string
		in         string
		want       *Account
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no public id",
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).LookupAccount: missing public id: parameter violation: error #102",
		},
		{
			name: "With non existing account id",
			in:   newAcctId,
		},
		{
			name: "With existing account id",
			in:   account.GetPublicId(),
			want: account,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAccount(context.Background(), tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_DeleteAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	account := TestAccount(t, conn, authMethod, "create-success")
	newAcctId, err := newAccountId(ctx, authMethod.GetPublicId(), authMethod.Issuer, "random-subject")
	require.NoError(t, err)
	tests := []struct {
		name       string
		scopeId    string
		in         string
		want       int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no scope id",
			scopeId:    "",
			in:         account.GetPublicId(),
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).DeleteAccount: missing scope id: parameter violation: error #100",
		},
		{
			name:       "With no public id",
			scopeId:    org.GetPublicId(),
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).DeleteAccount: missing public id: parameter violation: error #102",
		},
		{
			name:    "With non existing account id",
			scopeId: org.GetPublicId(),
			in:      newAcctId,
			want:    0,
		},
		{
			name:    "With existing account id",
			scopeId: org.GetPublicId(),
			in:      account.GetPublicId(),
			want:    1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteAccount(context.Background(), tt.scopeId, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_ListAccounts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod1 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod2 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod3 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice3.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	accounts1 := []*Account{
		TestAccount(t, conn, authMethod1, "create-success"),
		TestAccount(t, conn, authMethod1, "create-success2"),
		TestAccount(t, conn, authMethod1, "create-success3"),
	}
	accounts2 := []*Account{
		TestAccount(t, conn, authMethod2, "create-success"),
		TestAccount(t, conn, authMethod2, "create-success2"),
		TestAccount(t, conn, authMethod2, "create-success3"),
	}
	_ = accounts2

	tests := []struct {
		name       string
		in         string
		opts       []Option
		want       []*Account
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no auth method id",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "missing auth method id",
		},
		{
			name: "With no accounts id",
			in:   authMethod3.GetPublicId(),
			want: []*Account{},
		},
		{
			name: "With first auth method id",
			in:   authMethod1.GetPublicId(),
			want: accounts1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listAccounts(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				return
			}
			require.NoError(err)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

			sort.Slice(got, func(i, j int) bool {
				return strings.Compare(got[i].Subject, got[j].Subject) < 0
			})
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_ListAccounts_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	am := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	accountCount := 10
	for i := 0; i < accountCount; i++ {
		TestAccount(t, conn, am, fmt.Sprintf("create-success-%d", i))
	}

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: accountCount,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  accountCount,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  accountCount,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listAccounts(context.Background(), am.GetPublicId(), tt.listOpts...)
			// Transaction timestamp should be within ~10 seconds of now
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_UpdateAccount(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	changeName := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.Name = s
			return a
		}
	}

	changeDescription := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.Description = s
			return a
		}
	}

	makeNil := func() func(*Account) *Account {
		return func(a *Account) *Account {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*Account) *Account {
		return func(a *Account) *Account {
			return &Account{}
		}
	}

	deletePublicId := func() func(*Account) *Account {
		return func(a *Account) *Account {
			a.PublicId = ""
			return a
		}
	}

	nonExistentPublicId := func() func(*Account) *Account {
		return func(a *Account) *Account {
			a.PublicId = "abcd_OOOOOOOOOO"
			return a
		}
	}

	combine := func(fns ...func(a *Account) *Account) func(*Account) *Account {
		return func(a *Account) *Account {
			for _, fn := range fns {
				a = fn(a)
			}
			return a
		}
	}

	tests := []struct {
		name       string
		scopeId    string
		version    uint32
		orig       *Account
		chgFn      func(*Account) *Account
		masks      []string
		want       *Account
		wantCount  int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:    "nil-Account",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      makeNil(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing Account: parameter violation: error #100",
		},
		{
			name:    "nil-embedded-Account",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      makeEmbeddedNil(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing embedded Account: parameter violation: error #100",
		},
		{
			name:    "no-scope-id",
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "no-scope-id-test-name-repo",
				},
			},
			chgFn:      changeName("no-scope-id-test-update-name-repo"),
			masks:      []string{NameField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing scope id: parameter violation: error #100",
		},
		{
			name:    "missing-version",
			scopeId: org.GetPublicId(),
			orig: &Account{
				Account: &store.Account{
					Name: "missing-version-test-name-repo",
				},
			},
			chgFn:      changeName("test-update-name-repo"),
			masks:      []string{NameField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing version: parameter violation: error #100",
		},
		{
			name:    "no-public-id",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      deletePublicId(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing public id: parameter violation: error #102",
		},
		{
			name:    "updating-non-existent-Account",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "updating-non-existent-Account-test-name-repo",
				},
			},
			chgFn:      combine(nonExistentPublicId(), changeName("updating-non-existent-Account-test-update-name-repo")),
			masks:      []string{NameField},
			wantIsErr:  errors.RecordNotFound,
			wantErrMsg: "oidc.(Repository).UpdateAccount: abcd_OOOOOOOOOO: db.DoTx: oidc.(Repository).UpdateAccount: db.Update: record not found, search issue: error #1100: dbw.Update: dbw.lookupAfterWrite: dbw.LookupById: record not found",
		},
		{
			name:    "empty-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "empty-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("empty-field-mask-test-update-name-repo"),
			wantIsErr:  errors.EmptyFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing field mask: parameter violation: error #104",
		},
		{
			name:    "read-only-fields-in-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "read-only-fields-in-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("read-only-fields-in-field-mask-test-update-name-repo"),
			masks:      []string{"PublicId", "CreateTime", "UpdateTime", "AuthMethodId"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateAccount: PublicId: parameter violation: error #103",
		},
		{
			name:    "unknown-field-in-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "unknown-field-in-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("unknown-field-in-field-mask-test-update-name-repo"),
			masks:      []string{"Bilbo"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateAccount: Bilbo: parameter violation: error #103",
		},
		{
			name:    "change-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "change-name-test-name-repo",
				},
			},
			chgFn: changeName("change-name-test-update-name-repo"),
			masks: []string{NameField},
			want: &Account{
				Account: &store.Account{
					Name: "change-name-test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{DescriptionField},
			want: &Account{
				Account: &store.Account{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-name-and-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "change-name-and-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("change-name-and-description-test-update-name-repo")),
			masks: []string{NameField, DescriptionField},
			want: &Account{
				Account: &store.Account{
					Name:        "change-name-and-description-test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name: "delete-description-test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "do-not-delete-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "do-not-delete-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription(""), changeName("do-not-delete-description-test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-description-test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			orig := TestAccount(t, conn, am, tt.name, WithName(tt.orig.GetName()), WithDescription(tt.orig.GetDescription()))

			tt.orig.AuthMethodId = am.PublicId
			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateAccount(context.Background(), tt.scopeId, orig, tt.version, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			if tt.wantCount == 0 {
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NotNil(got)
			assertPublicId(t, globals.OidcAccountPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.AuthMethodId, got.AuthMethodId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				dbassert.IsNull(got, "name")
				return
			}
			assert.Equal(tt.want.Name, got.Name)
			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
				return
			}
			assert.Equal(tt.want.Description, got.Description)
			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_UpdateAccount_DupeNames(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		am := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, am, "create-success1")
		ab := TestAccount(t, conn, am, "create-success2")

		aa.Name = name
		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{NameField})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		ab.Name = name
		got2, gotCount2, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{NameField})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	})

	t.Run("valid-duplicate-names-diff-AuthMethods", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		ama := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, ama, "create-success1", WithName("test-name-aa"))

		amb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido2",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		ab := TestAccount(t, conn, amb, "create-success2", WithName("test-name-ab"))

		ab.Name = aa.Name
		got3, gotCount3, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{NameField})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(ab, got3)
		assert.Equal(aa.Name, got3.Name)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-authmethod-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		ama := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, ama, "create-success1")

		amb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido2",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		ab := TestAccount(t, conn, amb, "create-success2")

		assert.NotEqual(aa.AuthMethodId, ab.AuthMethodId)
		orig := aa.Clone()

		aa.AuthMethodId = ab.AuthMethodId
		assert.Equal(aa.AuthMethodId, ab.AuthMethodId)

		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{NameField})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.AuthMethodId, got1.AuthMethodId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}
