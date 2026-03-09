// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Test_encryptState_decryptState are unit tests for both encryptState(...) and decryptState(...)
func Test_encryptMessage_decryptMessage(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePrivateState, "alice-rp", "fido", WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]), WithSigningAlgs(RS256))

	now := time.Now()
	createTime := timestamppb.New(now.Truncate(time.Second))
	require.NoError(t, err)
	exp := timestamppb.New(now.Add(AttemptExpiration).Truncate(time.Second))

	tests := []struct {
		name            string
		wrapper         wrapping.Wrapper
		authMethod      *AuthMethod
		message         proto.Message
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:       "valid-request-state",
			wrapper:    db.TestWrapper(t),
			authMethod: testAuthMethod,
			message: &request.State{
				TokenRequestId:     "test-token-request-id",
				CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
				ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
				Nonce:              "test-nonce",
				FinalRedirectUrl:   "www.alice.com/final",
				ProviderConfigHash: 100,
			},
		},
		{
			name:       "valid-request-token",
			wrapper:    db.TestWrapper(t),
			authMethod: testAuthMethod,
			message: &request.Token{
				RequestId:      "test-token-request-id",
				ExpirationTime: &timestamp.Timestamp{Timestamp: exp},
			},
		},
		{
			name:       "missing-wrapper",
			wrapper:    nil,
			authMethod: testAuthMethod,
			message: &request.State{
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
			message: &request.State{
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
			wantErrContains: "missing message",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			encrypted, err := encryptMessage(ctx, tt.wrapper, tt.authMethod, tt.message)
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

			wrappedMsg, err := UnwrapMessage(ctx, encrypted)
			assert.Equalf(tt.authMethod.PublicId, wrappedMsg.AuthMethodId, "expected auth method %s and got: %s", tt.authMethod.PublicId, wrappedMsg.AuthMethodId)
			assert.Equalf(tt.authMethod.ScopeId, wrappedMsg.ScopeId, "expected scope id %s and got: %s", tt.authMethod.ScopeId, wrappedMsg.ScopeId)

			require.NoError(err)
			reqBytes, err := decryptMessage(ctx, tt.wrapper, wrappedMsg)
			require.NoError(err)

			var msg proto.Message
			switch v := tt.message.(type) {
			case *request.State:
				msg = &request.State{}
			case *request.Token:
				msg = &request.Token{}
			default:
				assert.Fail("unsupported message type: %v", v)
			}
			err = proto.Unmarshal(reqBytes, msg)
			require.NoError(err)
			assert.True(proto.Equal(tt.message, msg))
		})
	}
	t.Run("decryptState-bad-parameter-tests", func(t *testing.T) {
		tests := []struct {
			name            string
			wrapper         wrapping.Wrapper
			wrappedMsg      *request.Wrapper
			wantErrMatch    *errors.Template
			wantErrContains string
		}{
			{
				name:            "missing-wrapper",
				wrappedMsg:      &request.Wrapper{},
				wantErrMatch:    errors.T(errors.InvalidParameter),
				wantErrContains: "missing wrapping wrapper",
			},
			{
				name:            "missing-encrypted-state",
				wrapper:         db.TestWrapper(t),
				wantErrMatch:    errors.T(errors.InvalidParameter),
				wantErrContains: "missing wrapped request",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert := assert.New(t)
				_, err = decryptMessage(ctx, tt.wrapper, tt.wrappedMsg)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Contains(err.Error(), tt.wantErrContains)
			})
		}
	})
}

func Test_requestWrappingWrapper(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePrivateState, "alice-rp", "fido", WithApiUrl(TestConvertToUrls(t, "https://alice.com/callback")[0]), WithSigningAlgs(RS256))

	oidcWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeOidc)
	require.NoError(t, err)

	tests := []struct {
		name         string
		setupFn      func() (string, string)
		opt          []Option
		wantErrMatch *errors.Template
	}{
		{
			name:    "simple-valid",
			setupFn: func() (string, string) { return org.PublicId, testAuthMethod.PublicId },
		},
		{
			name:         "missing-scope",
			setupFn:      func() (string, string) { return "", testAuthMethod.PublicId },
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "missing-auth-method-id",
			setupFn:      func() (string, string) { return org.PublicId, "" },
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			scopeId, authMethodId := tt.setupFn()

			keyId, err := oidcWrapper.KeyId(ctx)
			require.NoError(err)
			wantKeyId := derivedKeyId(derivedKeyPurposeState, keyId, authMethodId)
			kmsCache.GetDerivedPurposeCache().Delete(wantKeyId)

			reqWrapper, err := requestWrappingWrapper(ctx, repo.kms, scopeId, authMethodId, tt.opt...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(reqWrapper)
				cachedWrapper, found := kmsCache.GetDerivedPurposeCache().Load(wantKeyId)
				assert.False(found)
				assert.Empty(cachedWrapper)
				return
			}
			require.NoError(err)
			assert.NotEmpty(requestWrappingWrapper)
			keyId, err = reqWrapper.KeyId(ctx)
			require.NoError(err)
			wrapperType, err := reqWrapper.Type(ctx)
			require.NoError(err)
			assert.Equalf(wantKeyId, keyId, "expected key id %s and got: %s", wantKeyId, keyId)
			assert.Equalf(wrapping.WrapperTypeAead, wrapperType, "expected type %s and got: %s", wrapping.WrapperTypeAead, wrapperType)
			keyBytes, err := reqWrapper.(*aead.Wrapper).KeyBytes(ctx)
			require.NoError(err)
			assert.NotEmpty(keyBytes)

			cachedWrapper, found := kmsCache.GetDerivedPurposeCache().Load(wantKeyId)
			require.True(found)
			require.NotEmpty(cachedWrapper)
			assert.Equal(reqWrapper, cachedWrapper)

			dupWrapper, err := requestWrappingWrapper(ctx, repo.kms, scopeId, authMethodId, tt.opt...)
			require.NoError(err)
			require.NotEmpty(dupWrapper)
			assert.Equal(reqWrapper, dupWrapper)
		})
	}
}

func Test_derivedKeyPurpose_String(t *testing.T) {
	tests := []struct {
		purpose derivedKeyPurpose
		want    string
	}{
		{100, "oidc_unknown"},
		{derivedKeyPurposeUnknown, "oidc_unknown"},
		{derivedKeyPurposeState, "oidc_state"},
	}
	for _, tt := range tests {
		t.Run(tt.purpose.String(), func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.purpose.String(), "wanted %s and got: %s", tt.want, tt.purpose.String())
		})
	}
}
