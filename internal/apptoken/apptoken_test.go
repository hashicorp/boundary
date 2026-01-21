// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppToken_IsActive(t *testing.T) {
	now := timestamp.Now()
	past := timestamp.New(now.AsTime().Add(-1 * time.Hour))
	future := timestamp.New(now.AsTime().Add(1 * time.Hour))

	tests := []struct {
		name  string
		token *AppToken
		want  bool
	}{
		{
			name: "active token",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            future,
				ApproximateLastAccessTime: now,
				TimeToStaleSeconds:        3600,
			},
			want: true,
		},
		{
			name: "revoked token",
			token: &AppToken{
				Revoked:                   true,
				ExpirationTime:            future,
				ApproximateLastAccessTime: now,
				TimeToStaleSeconds:        3600,
			},
			want: false,
		},
		{
			name: "expired token",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            past,
				ApproximateLastAccessTime: now,
				TimeToStaleSeconds:        3600,
			},
			want: false,
		},
		{
			name: "stale token",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            future,
				ApproximateLastAccessTime: past,
				TimeToStaleSeconds:        1800,
			},
			want: false,
		},
		{
			name: "no TimeToStaleSeconds set",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            future,
				ApproximateLastAccessTime: past,
				TimeToStaleSeconds:        0,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.token.IsActive())
		})
	}
}

func TestAppToken_encrypt_decrypt(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testWrapper := db.TestWrapper(t)
	tests := []struct {
		name            string
		ctx             context.Context
		cipher          wrapping.Wrapper
		atc             *appTokenCipher
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:   "valid",
			ctx:    testCtx,
			cipher: testWrapper,
			atc: &appTokenCipher{
				AppTokenCipher: &store.AppTokenCipher{
					Token: "test-token",
				},
			},
		},
		{
			name: "missing-cipher",
			ctx:  testCtx,
			atc: &appTokenCipher{
				AppTokenCipher: &store.AppTokenCipher{
					Token: "test-token",
				},
			},
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "nil wrapper passed in",
		},
		{
			name: "encrypt-err",
			ctx:  testCtx,
			cipher: &kms.MockWrapper{
				Wrapper:    testWrapper,
				EncryptErr: fmt.Errorf("test encrypt error"),
			},
			atc: &appTokenCipher{
				AppTokenCipher: &store.AppTokenCipher{
					Token: "test-token",
				},
			},
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "test encrypt error",
		},
		{
			name: "keyId-err",
			ctx:  testCtx,
			cipher: &kms.MockWrapper{
				Wrapper:  testWrapper,
				KeyIdErr: fmt.Errorf("test key id error"),
			},
			atc: &appTokenCipher{
				AppTokenCipher: &store.AppTokenCipher{
					Token: "test-token",
				},
			},
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "test key id error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.Empty(tc.atc.KeyId)
			require.Empty(tc.atc.CtToken)

			err := tc.atc.encrypt(tc.ctx, tc.cipher)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrCode != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotEmpty(tc.atc.KeyId)
			assert.NotEmpty(tc.atc.CtToken)
		})
	}
	t.Run("decrypt-valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		originalAtc := &appTokenCipher{
			AppTokenCipher: &store.AppTokenCipher{
				Token: "test-token",
			},
		}
		err := originalAtc.encrypt(testCtx, testWrapper)
		require.NoError(err)
		require.NotEmpty(originalAtc.CtToken)

		decryptedAtc := &appTokenCipher{
			AppTokenCipher: &store.AppTokenCipher{
				CtToken: originalAtc.CtToken,
				KeyId:   originalAtc.KeyId,
			},
		}
		err = decryptedAtc.decrypt(testCtx, testWrapper)
		require.NoError(err)
		assert.Equal(originalAtc.Token, decryptedAtc.Token)
	})
	t.Run("decrypt-missing-cipher", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		atc := &appTokenCipher{
			AppTokenCipher: &store.AppTokenCipher{
				Token: "test-token",
			},
		}
		err := atc.decrypt(testCtx, nil)
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.Decrypt), err))
		assert.Contains(err.Error(), "nil wrapper passed in")
	})
	t.Run("decrypt-err", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		originalAtc := &appTokenCipher{
			AppTokenCipher: &store.AppTokenCipher{
				Token: "test-token",
			},
		}
		err := originalAtc.encrypt(testCtx, testWrapper)
		require.NoError(err)
		require.NotEmpty(originalAtc.CtToken)

		decryptingWrapper := &kms.MockWrapper{
			Wrapper:    testWrapper,
			DecryptErr: fmt.Errorf("test decrypt error"),
		}

		decryptedAtc := &appTokenCipher{
			AppTokenCipher: &store.AppTokenCipher{
				CtToken: originalAtc.CtToken,
				KeyId:   originalAtc.KeyId,
			},
		}
		err = decryptedAtc.decrypt(testCtx, decryptingWrapper)
		require.Error(err)
		assert.True(errors.Match(errors.T(errors.Decrypt), err))
		assert.Contains(err.Error(), "test decrypt error")
	})
}
