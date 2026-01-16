// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthMethod_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	new := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

	tests := []struct {
		name      string
		update    *AuthMethod
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *AuthMethod {
				cp := new.Clone()
				cp.PublicId = "p_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *AuthMethod {
				cp := new.Clone()
				cp.CreateTime = &ts
				return cp
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *AuthMethod {
				cp := new.Clone()
				cp.ScopeId = "o_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := new.Clone()
			orig.SetTableName(defaultAuthMethodTableName)
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			tt.update.SetTableName(defaultAuthMethodTableName)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.SetTableName(defaultAuthMethodTableName)
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestAudClaim_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithAudClaims("alice.com"))

	new := AllocAudClaim()
	require.NoError(t, rw.LookupWhere(ctx, &new, "oidc_method_id = ? and aud_claim = ?", []any{am.PublicId, "alice.com"}))

	tests := []struct {
		name      string
		update    *AudClaim
		fieldMask []string
	}{
		{
			name: "oidc_method_id",
			update: func() *AudClaim {
				cp := new.Clone()
				cp.OidcMethodId = "p_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *AudClaim {
				cp := new.Clone()
				cp.CreateTime = &ts
				return cp
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "aud",
			update: func() *AudClaim {
				cp := new.Clone()
				cp.Aud = "o_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"Aud"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := new.Clone()
			orig.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and aud_claim = ?", []any{orig.OidcMethodId, orig.Aud}))

			require.NoError(err)

			tt.update.SetTableName(defaultAuthMethodTableName)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and aud_claim = ?", []any{after.OidcMethodId, after.Aud}))

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestCertificate_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	x509, pem := testGenerateCA(t, "www.alice.com")

	_, pem2 := testGenerateCA(t, "www.bob.com")

	am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithCertificates(x509))

	new := AllocCertificate()
	require.NoError(t, rw.LookupWhere(ctx, &new, "oidc_method_id = ? and certificate = ?", []any{am.PublicId, pem}))

	tests := []struct {
		name      string
		update    *Certificate
		fieldMask []string
	}{
		{
			name: "oidc_method_id",
			update: func() *Certificate {
				cp := new.Clone()
				cp.OidcMethodId = "p_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Certificate {
				cp := new.Clone()
				cp.CreateTime = &ts
				return cp
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "cert",
			update: func() *Certificate {
				cp := new.Clone()
				cp.Cert = pem2
				return cp
			}(),
			fieldMask: []string{"Cert"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := new.Clone()
			orig.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and certificate = ?", []any{orig.OidcMethodId, orig.Cert}))

			require.NoError(err)

			tt.update.SetTableName(defaultAuthMethodTableName)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and certificate = ?", []any{after.OidcMethodId, after.Cert}))

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestSigningAlg_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithSigningAlgs(RS256))

	new := AllocSigningAlg()
	require.NoError(t, rw.LookupWhere(ctx, &new, "oidc_method_id = ? and signing_alg_name = ?", []any{am.PublicId, RS256}))

	tests := []struct {
		name      string
		update    *SigningAlg
		fieldMask []string
	}{
		{
			name: "oidc_method_id",
			update: func() *SigningAlg {
				cp := new.Clone()
				cp.OidcMethodId = "p_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *SigningAlg {
				cp := new.Clone()
				cp.CreateTime = &ts
				return cp
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "alg",
			update: func() *SigningAlg {
				cp := new.Clone()
				cp.Alg = string(RS384)
				return cp
			}(),
			fieldMask: []string{"Alg"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := new.Clone()
			orig.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and signing_alg_name = ?", []any{orig.OidcMethodId, orig.Alg}))

			require.NoError(err)

			tt.update.SetTableName(defaultAuthMethodTableName)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and signing_alg_name = ?", []any{after.OidcMethodId, after.Alg}))

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestAccount_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	u := TestConvertToUrls(t, "https://alice.com")[0]

	am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithIssuer(u), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

	new := TestAccount(t, conn, am, "alice", WithName("Alice"), WithDescription("alice's account"), WithFullName("Alice Smith"), WithEmail("alice@alice.com"))

	tests := []struct {
		name      string
		update    *Account
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *Account {
				cp := new.Clone()
				cp.PublicId = "p_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Account {
				cp := new.Clone()
				cp.CreateTime = &ts
				return cp
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "update time",
			update: func() *Account {
				cp := new.Clone()
				cp.UpdateTime = &ts
				return cp
			}(),
			fieldMask: []string{"UpdateTime"},
		},
		{
			name: "oidc-auth-method-id",
			update: func() *Account {
				cp := new.Clone()
				cp.AuthMethodId = "aodic_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"AuthMethodId"},
		},
		{
			name: "issuer",
			update: func() *Account {
				cp := new.Clone()
				cp.Issuer = "bob.com"
				return cp
			}(),
			fieldMask: []string{IssuerField},
		},
		{
			name: "subject",
			update: func() *Account {
				cp := new.Clone()
				cp.Subject = "bob"
				return cp
			}(),
			fieldMask: []string{"Subject"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := new.Clone()
			orig.SetTableName(defaultAccountTableName)
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			tt.update.SetTableName(defaultAccountTableName)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.SetTableName(defaultAccountTableName)
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestPrompt_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithPrompts(SelectAccount))

	new := AllocPrompt()
	require.NoError(t, rw.LookupWhere(ctx, &new, "oidc_method_id = ? and prompt = ?", []any{am.PublicId, SelectAccount}))

	tests := []struct {
		name      string
		update    *Prompt
		fieldMask []string
	}{
		{
			name: "oidc_method_id",
			update: func() *Prompt {
				cp := new.Clone()
				cp.OidcMethodId = "p_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Prompt {
				cp := new.Clone()
				cp.CreateTime = &ts
				return cp
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "prompt",
			update: func() *Prompt {
				cp := new.Clone()
				cp.PromptParam = string(Consent)
				return cp
			}(),
			fieldMask: []string{"PromptParam"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := new.Clone()
			orig.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and prompt = ?", []any{orig.OidcMethodId, orig.PromptParam}))

			require.NoError(err)

			tt.update.SetTableName(defaultAuthMethodTableName)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.SetTableName(defaultAuthMethodTableName)
			require.NoError(rw.LookupWhere(ctx, &new, "oidc_method_id = ? and prompt = ?", []any{after.OidcMethodId, after.PromptParam}))

			assert.True(proto.Equal(orig, after))
		})
	}
}
