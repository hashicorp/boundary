// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_DeleteAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()

	tests := []struct {
		name            string
		authMethod      *AuthMethod
		wantRowsDeleted int
		wantErrMatch    *errors.Template
	}{
		{
			name: "valid",
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "alices-dogs-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
			}(),
			wantRowsDeleted: 1,
		},
		{
			name: "valid-with-prompts",
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(
					t,
					conn,
					databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice_rp",
					"alices-dogs-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]),
					WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]),
					WithPrompts(SelectAccount),
				)
			}(),
			wantRowsDeleted: 1,
		},
		{
			name:         "no-public-id",
			authMethod:   func() *AuthMethod { am := AllocAuthMethod(); return &am }(),
			wantErrMatch: errors.T(errors.InvalidPublicId),
		},
		{
			name: "not-found",
			authMethod: func() *AuthMethod {
				am := AllocAuthMethod()
				var err error
				am.PublicId, err = newAuthMethodId(ctx)
				require.NoError(t, err)
				return &am
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			require.NoError(err)
			deletedRows, err := repo.DeleteAuthMethod(ctx, tt.authMethod.PublicId)
			if tt.wantErrMatch != nil {
				require.Error(err)

				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err: %q got: %q", tt.wantErrMatch.Msg, err)

				assert.Equalf(0, deletedRows, "expected 0 deleted rows and got %d", deletedRows)

				err := db.TestVerifyOplog(t, rw, tt.authMethod.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", tt.authMethod.PublicId)
				assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "expected error code %s and got %s", errors.RecordNotFound, err)

				return
			}
			require.NoError(err)
			assert.Equalf(tt.wantRowsDeleted, deletedRows, "expected rows deleted == %d and got %d", tt.wantRowsDeleted, deletedRows)

			if tt.wantRowsDeleted > 0 {
				err = db.TestVerifyOplog(t, rw, tt.authMethod.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
			}
			found, err := repo.LookupAuthMethod(ctx, tt.authMethod.PublicId)
			require.NoError(err)
			assert.Nil(found)
		})
	}
}
