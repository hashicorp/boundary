package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Test_encryptState_decryptState are unit tests for both encryptState(...) and decryptState(...)
func Test_encryptState_decryptState(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePrivateState, TestConvertToUrls(t, "https://www.alice.com")[0], "alice-rp", "fido")

	now := time.Now()
	createTime, err := ptypes.TimestampProto(now.Truncate(time.Second))
	require.NoError(t, err)
	exp, err := ptypes.TimestampProto(now.Add(AttemptExpiration).Truncate(time.Second))
	require.NoError(t, err)

	tests := []struct {
		name            string
		wrapper         wrapping.Wrapper
		authMethod      *AuthMethod
		reqState        *request.State
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:       "valid",
			wrapper:    db.TestWrapper(t),
			authMethod: testAuthMethod,
			reqState: &request.State{
				TokenRequestId:     "test-token-request-id",
				CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
				ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
				Nonce:              "test-nonce",
				FinalRedirectUrl:   "www.alice.com/final",
				ProviderConfigHash: 100,
			},
		},
		{
			name:       "missing-wrapper",
			wrapper:    nil,
			authMethod: testAuthMethod,
			reqState: &request.State{
				TokenRequestId:     "test-token-request-id",
				CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
				ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
				Nonce:              "test-nonce",
				FinalRedirectUrl:   "www.alice.com/final",
				ProviderConfigHash: 100,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing wrapper",
		},
		{
			name:    "missing-auth-method",
			wrapper: db.TestWrapper(t),
			reqState: &request.State{
				TokenRequestId:     "test-token-request-id",
				CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
				ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
				Nonce:              "test-nonce",
				FinalRedirectUrl:   "www.alice.com/final",
				ProviderConfigHash: 100,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method",
		},
		{
			name:            "missing-req-state",
			wrapper:         db.TestWrapper(t),
			authMethod:      testAuthMethod,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing request state",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			encrypted, err := encryptState(ctx, tt.wrapper, tt.authMethod, tt.reqState)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Empty(encrypted)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotEmpty(encrypted)

			gotScopeId, gotAuthMethodId, reqState, err := decryptState(ctx, tt.wrapper, encrypted)
			require.NoError(err)
			assert.Equalf(tt.authMethod.PublicId, gotAuthMethodId, "expected auth method %s and got: %s", tt.authMethod.PublicId, gotAuthMethodId)
			assert.Equalf(tt.authMethod.ScopeId, gotScopeId, "expected scope id %s and got: %s", tt.authMethod.ScopeId, gotScopeId)
			assert.True(proto.Equal(tt.reqState, reqState))
		})
	}
	t.Run("decryptState-bad-parameter-tests", func(t *testing.T) {
		tests := []struct {
			name            string
			wrapper         wrapping.Wrapper
			encryptedState  string
			wantErrMatch    *errors.Template
			wantErrContains string
		}{
			{
				name:            "missing-wrapper",
				encryptedState:  "dummy-encrypted-state",
				wantErrMatch:    errors.T(errors.InvalidParameter),
				wantErrContains: "missing wrapper",
			},
			{
				name:            "missing-encrypted-state",
				wrapper:         db.TestWrapper(t),
				wantErrMatch:    errors.T(errors.InvalidParameter),
				wantErrContains: "missing encoded/encrypted state",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert := assert.New(t)
				_, _, _, err := decryptState(ctx, tt.wrapper, tt.encryptedState)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Contains(err.Error(), tt.wantErrContains, "missing wrapper")
			})
		}
	})

}
