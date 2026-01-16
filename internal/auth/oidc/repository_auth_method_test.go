// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_upsertAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	rw := db.New(conn)

	r, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	amActivePriv := TestAuthMethod(
		t,
		conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice_rp", "fido",
		WithApiUrl(TestConvertToUrls(t, "https://alice-active-priv.com/callback")[0]),
		WithSigningAlgs(RS256))

	amWithMapping := TestAuthMethod(
		t,
		conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice_rp", "fido",
		WithAccountClaimMap(map[string]AccountToClaim{"oid": ToSubClaim}),
		WithApiUrl(TestConvertToUrls(t, "https://alice-active-priv.com/callback")[0]),
		WithSigningAlgs(RS256))

	tests := []struct {
		name            string
		am              *AuthMethod
		idClaims        map[string]any
		atClaims        map[string]any
		wantAcct        *Account
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:     "success-defaults",
			am:       amActivePriv,
			idClaims: map[string]any{"iss": "https://alice-active-priv.com", "sub": "success-defaults"},
			atClaims: map[string]any{},
			wantAcct: &Account{Account: &store.Account{
				AuthMethodId:   amActivePriv.PublicId,
				Issuer:         "https://alice-active-priv.com",
				Subject:        "success-defaults",
				TokenClaims:    `{"iss":"https://alice-active-priv.com","sub":"success-defaults"}`,
				UserinfoClaims: "{}",
			}},
		},
		{
			name:     "success-atTk-full-name-and-email",
			am:       amActivePriv,
			idClaims: map[string]any{"iss": "https://alice-active-priv.com", "sub": "success-atTk-full-name-and-email"},
			atClaims: map[string]any{"name": "alice eve-smith", "email": "alice@alice.com"},
			wantAcct: &Account{Account: &store.Account{
				AuthMethodId:   amActivePriv.PublicId,
				Issuer:         "https://alice-active-priv.com",
				Subject:        "success-atTk-full-name-and-email",
				Email:          "alice@alice.com",
				FullName:       "alice eve-smith",
				TokenClaims:    `{"iss":"https://alice-active-priv.com","sub":"success-atTk-full-name-and-email"}`,
				UserinfoClaims: `{"email":"alice@alice.com","name":"alice eve-smith"}`,
			}},
		},
		{
			name:     "success-idTk-full-name-and-email",
			am:       amActivePriv,
			idClaims: map[string]any{"iss": "https://alice-active-priv.com", "sub": "success-idTk-full-name-and-email", "name": "alice eve-smith", "email": "alice@alice.com"},
			atClaims: map[string]any{},
			wantAcct: &Account{Account: &store.Account{
				AuthMethodId:   amActivePriv.PublicId,
				Issuer:         "https://alice-active-priv.com",
				Subject:        "success-idTk-full-name-and-email",
				Email:          "alice@alice.com",
				FullName:       "alice eve-smith",
				TokenClaims:    `{"email":"alice@alice.com","iss":"https://alice-active-priv.com","name":"alice eve-smith","sub":"success-idTk-full-name-and-email"}`,
				UserinfoClaims: `{}`,
			}},
		},
		{
			name:     "success-map-idTk",
			am:       amWithMapping,
			idClaims: map[string]any{"iss": "https://alice-active-priv.com", "sub": "success-defaults", "oid": "success-map"},
			atClaims: map[string]any{},
			wantAcct: &Account{Account: &store.Account{
				AuthMethodId:   amWithMapping.PublicId,
				Issuer:         "https://alice-active-priv.com",
				Subject:        "success-map",
				TokenClaims:    `{"iss":"https://alice-active-priv.com","oid":"success-map","sub":"success-defaults"}`,
				UserinfoClaims: `{}`,
			}},
		},
		{
			name:            "non-existent-auth-method-scope-id",
			am:              func() *AuthMethod { cp := amActivePriv.Clone(); cp.ScopeId = "non-existent-scope-id"; return cp }(),
			idClaims:        map[string]any{"iss": "https://alice.com", "sub": "non-existent-auth-method-scope-id"},
			atClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to get oplog wrapper",
		},
		{
			name:            "non-parsable-issuer",
			am:              amActivePriv,
			idClaims:        map[string]any{"iss": ":::::alice.com", "sub": "non-parsable-issuer"},
			atClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to parse issuer",
		},
		{
			name:            "empty-sub",
			am:              amActivePriv,
			idClaims:        map[string]any{"iss": "https://alice.com", "sub": ""},
			atClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing subject",
		},
		{
			name:            "empty-issuer",
			am:              amActivePriv,
			idClaims:        map[string]any{"iss": "", "sub": "bad-issuer"},
			atClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing issuer",
		},
		{
			name:            "missing-id-token-issuer",
			am:              amActivePriv,
			idClaims:        map[string]any{},
			atClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "issuer is not present in ID Token",
		},
		{
			name:            "missing-id-token-sub",
			am:              amActivePriv,
			idClaims:        map[string]any{"iss": "https://alice.com"},
			atClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "to account subject and it is not present in ID Token",
		},
		{
			name:            "missing-id-token-claims",
			am:              amActivePriv,
			atClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing ID Token claims",
		},
		{
			name:            "missing-access-token-claims",
			am:              amActivePriv,
			idClaims:        map[string]any{},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing Access Token claims",
		},
		{
			name:            "missing-auth-method",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotAcct, err := r.upsertAccount(ctx, tt.am, tt.idClaims, tt.atClaims)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "got err %s but wanted: %+v", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			tt.wantAcct.PublicId = gotAcct.PublicId
			tt.wantAcct.Version = gotAcct.Version
			tt.wantAcct.CreateTime = gotAcct.CreateTime
			tt.wantAcct.UpdateTime = gotAcct.UpdateTime
			require.NoError(err)
			ok := proto.Equal(tt.wantAcct.Account, gotAcct.Account)
			assert.True(ok)
			if !ok {
				assert.Equalf(tt.wantAcct, gotAcct, "using assert.Equal to just show the diff between want and got")
			}
		})
	}
}

func Test_upsertOplog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oplogWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeOplog)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	tests := []struct {
		name            string
		writer          db.Writer
		wrapper         wrapping.Wrapper
		op              oplog.OpType
		scopeId         string
		acct            *Account
		fieldMasks      []string
		nullFields      []string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:    "create-success",
			writer:  rw,
			wrapper: oplogWrapper,
			op:      oplog.OpType_OP_TYPE_CREATE,
			scopeId: org.PublicId,
			acct:    TestAccount(t, conn, testAuthMethod, "create-success"),
		},
		{
			name:       "update-success-withFieldMask-only",
			writer:     rw,
			wrapper:    oplogWrapper,
			op:         oplog.OpType_OP_TYPE_UPDATE,
			fieldMasks: []string{"FullName"},
			scopeId:    org.PublicId,
			acct:       TestAccount(t, conn, testAuthMethod, "update-success-withFieldMask-only"),
		},
		{
			name:       "update-success-withNullFields-only",
			writer:     rw,
			wrapper:    oplogWrapper,
			op:         oplog.OpType_OP_TYPE_UPDATE,
			nullFields: []string{"FullName"},
			scopeId:    org.PublicId,
			acct:       TestAccount(t, conn, testAuthMethod, "update-success-withNullFields-only"),
		},
		{
			name:            "update-missing-fieldMask-and-nullFields",
			writer:          rw,
			wrapper:         oplogWrapper,
			op:              oplog.OpType_OP_TYPE_UPDATE,
			scopeId:         org.PublicId,
			acct:            TestAccount(t, conn, testAuthMethod, "update-missing-fieldMask-and-nullFields"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "update operations must specify field masks and/or null masks",
		},
		{
			name:            "missing-writer",
			wrapper:         oplogWrapper,
			op:              oplog.OpType_OP_TYPE_CREATE,
			scopeId:         org.PublicId,
			acct:            TestAccount(t, conn, testAuthMethod, "missing-writer"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing db writer",
		},
		{
			name:            "missing-oplog-wrapper",
			writer:          rw,
			op:              oplog.OpType_OP_TYPE_CREATE,
			scopeId:         org.PublicId,
			acct:            TestAccount(t, conn, testAuthMethod, "missing-oplog-wrapper"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing oplog wrapper",
		},
		{
			name:            "bad-op-type",
			writer:          rw,
			wrapper:         oplogWrapper,
			op:              oplog.OpType_OP_TYPE_DELETE,
			scopeId:         org.PublicId,
			acct:            TestAccount(t, conn, testAuthMethod, "bad-op-type"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not a supported operation",
		},
		{
			name:            "missing-scope-id",
			writer:          rw,
			wrapper:         oplogWrapper,
			op:              oplog.OpType_OP_TYPE_UPDATE,
			acct:            TestAccount(t, conn, testAuthMethod, "missing-scope-id"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name:            "missing-account",
			writer:          rw,
			wrapper:         oplogWrapper,
			op:              oplog.OpType_OP_TYPE_UPDATE,
			scopeId:         org.PublicId,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing account",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// start with no oplog entries
			_, err = rw.Exec(ctx, "delete from oplog_entry", nil)
			require.NoError(err)

			err := upsertOplog(ctx, tt.writer, tt.wrapper, tt.op, tt.scopeId, tt.acct, tt.fieldMasks, tt.nullFields)
			if tt.wantErrMatch != nil {
				require.Error(err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				if tt.acct != nil {
					// check for create
					err := db.TestVerifyOplog(t, rw, tt.acct.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", tt.acct.AuthMethodId)

					// check for update
					err = db.TestVerifyOplog(t, rw, tt.acct.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", tt.acct.AuthMethodId)
				}
				return
			}
			require.NoError(err)
			err = db.TestVerifyOplog(t, rw, tt.acct.PublicId, db.WithOperation(tt.op), db.WithCreateNotBefore(10*time.Second))
			require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
		})
	}
}
