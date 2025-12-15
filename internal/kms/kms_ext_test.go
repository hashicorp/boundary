// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: This is a sequential test that relies on the actions that have come
// before. Please see the comments for details.
func TestKms(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	extWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, extWrapper)
	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, extWrapper))

	// This next sequence is run twice to ensure that calling for the keys twice
	// returns the same value each time and doesn't simply populate more keys
	// into the KMS object
	keyBytes := map[string]bool{}
	keyIds := map[string]bool{}
	for i := 1; i < 3; i++ {
		// This iterates through wrappers for all three scopes and four purposes,
		// ensuring that the key bytes and IDs are different for each of them,
		// simulating calling the KMS object from different scopes for different
		// purposes and ensuring the keys are different when that happens.
		t.Run(fmt.Sprintf("verify wrappers different x %d", i), func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			for _, scopeId := range []string{scope.Global.String(), org.GetPublicId(), proj.GetPublicId()} {
				for _, purpose := range []kms.KeyPurpose{kms.KeyPurposeUnknown, kms.KeyPurposeOplog, kms.KeyPurposeDatabase, kms.KeyPurposeSessions, kms.KeyPurposeTokens} {
					wrapper, err := kmsCache.GetWrapper(ctx, scopeId, purpose)
					if purpose == kms.KeyPurposeUnknown {
						require.Error(err)
						continue
					}
					require.NoError(err)
					multi, ok := wrapper.(*multi.PooledWrapper)
					require.True(ok)
					mKeyId, err := multi.KeyId(ctx)
					require.NoError(err)
					aeadWrapper, ok := multi.WrapperForKeyId(mKeyId).(*aead.Wrapper)
					require.True(ok)
					aeadKeyId, err := aeadWrapper.KeyId(ctx)
					require.NoError(err)
					wrapperBytes, err := aeadWrapper.KeyBytes(ctx)
					require.NoError(err)
					foundKeyBytes := keyBytes[base64.StdEncoding.EncodeToString(wrapperBytes)]
					foundKeyId := keyIds[aeadKeyId]
					if i == 1 {
						assert.False(foundKeyBytes)
						assert.False(foundKeyId)
						wrapperBytes, err := aeadWrapper.KeyBytes(ctx)
						require.NoError(err)
						keyBytes[base64.StdEncoding.EncodeToString(wrapperBytes)] = true
						keyIds[aeadKeyId] = true
					} else {
						assert.True(foundKeyBytes)
						assert.True(foundKeyId)
					}
				}
			}
		})
	}
}

func TestKms_ReconcileKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	tests := []struct {
		name            string
		kms             *kms.Kms
		scopeIds        []string
		reader          io.Reader
		setup           func(*kms.Kms)
		wantPurpose     []kms.KeyPurpose
		wantErr         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-reader",
			kms:             kms.TestKms(t, conn, wrapper),
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing rand reader",
		},
		{
			name:            "reader-interface-is-nil",
			kms:             kms.TestKms(t, conn, wrapper),
			reader:          func() io.Reader { var sr *strings.Reader; var r io.Reader = sr; return r }(),
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing rand reader",
		},
		{
			name:    "nothing-to-reconcile",
			kms:     kms.TestKms(t, conn, wrapper),
			reader:  rand.Reader,
			wantErr: false,
		},
		{
			name:   "reconcile-audit-key",
			kms:    kms.TestKms(t, conn, wrapper),
			reader: rand.Reader,
			setup: func(k *kms.Kms) {
				kms.TestKmsDeleteKeyPurpose(t, conn, kms.KeyPurposeAudit)
				_, err := k.GetWrapper(testCtx, scope.Global.String(), kms.KeyPurposeAudit)
				require.Error(t, err)
			},
			wantPurpose: []kms.KeyPurpose{kms.KeyPurposeAudit},
			wantErr:     false,
		},
		{
			name:     "reconcile-oidc-key-multiple-scopes",
			kms:      kms.TestKms(t, conn, wrapper),
			scopeIds: []string{org.PublicId, org2.PublicId},
			reader:   rand.Reader,
			setup: func(k *kms.Kms) {
				// create initial keys for the test scope ids...
				for _, id := range []string{org.PublicId, org2.PublicId} {
					err := k.CreateKeys(testCtx, id)
					require.NoError(t, err)
				}
				kms.TestKmsDeleteKeyPurpose(t, conn, kms.KeyPurposeOidc)

				// make sure the kms is in the proper state for the unit test
				// before proceeding.
				for _, id := range []string{org.PublicId, org2.PublicId} {
					_, err := k.GetWrapper(testCtx, id, kms.KeyPurposeOidc)
					require.Error(t, err)
				}
			},
			wantPurpose: []kms.KeyPurpose{kms.KeyPurposeOidc},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			// start with no keys...
			kms.TestKmsDeleteAllKeys(t, conn)

			// create initial keys for the global scope...
			err := tt.kms.CreateKeys(context.Background(), scope.Global.String())
			require.NoError(err)

			if tt.setup != nil {
				tt.setup(tt.kms)
			}
			err = tt.kms.ReconcileKeys(testCtx, tt.reader, kms.WithScopeIds(tt.scopeIds...))
			if tt.wantErr {
				assert.Error(err)
				if tt.wantErrMatch != nil {
					assert.Truef(errors.Match(tt.wantErrMatch, err), "expected %q and got err: %+v", tt.wantErrMatch.Code, err)
				}
				if tt.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tt.wantErrContains))
				}
				return
			}
			assert.NoError(err)
			if len(tt.scopeIds) > 0 {
				for _, id := range tt.scopeIds {
					for _, p := range tt.wantPurpose {
						_, err := tt.kms.GetWrapper(testCtx, id, p)
						require.NoError(err)
					}
				}
			}
			_, err = tt.kms.GetWrapper(testCtx, scope.Global.String(), kms.KeyPurposeAudit)
			require.NoError(err)
		})
	}
}

func TestKms_GetDerivedPurposeCache(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	derivedWrapper := db.TestWrapper(t)
	kmsCache.GetDerivedPurposeCache().Store(1, derivedWrapper)

	v, ok := kmsCache.GetDerivedPurposeCache().Load(1)
	assert.True(ok)
	assert.Equal(derivedWrapper, v)
}

func TestKms_VerifyGlobalRoot(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	assert.Error(kmsCache.VerifyGlobalRoot(testCtx))

	require.NoError(kmsCache.CreateKeys(testCtx, "global"))
	assert.NoError(kmsCache.VerifyGlobalRoot(testCtx))
}

func TestKms_GetWrapper(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	require.NoError(t, kmsCache.CreateKeys(testCtx, "global"))
	tests := []struct {
		name            string
		kms             *kms.Kms
		purpose         kms.KeyPurpose
		scopeId         string
		opt             []kms.Option
		wantErr         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-purpose",
			kms:             kmsCache,
			scopeId:         "global",
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing purpose",
		},
		{
			name:            "missing-scope-id",
			kms:             kmsCache,
			purpose:         kms.KeyPurposeDatabase,
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name:    "success",
			kms:     kmsCache,
			purpose: kms.KeyPurposeDatabase,
			scopeId: "global",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.kms.GetWrapper(testCtx, tc.scopeId, tc.purpose, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "expected %q and got err: %+v", tc.wantErrMatch.Code, err)
				}
				if tc.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tc.wantErrContains))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
		})
	}
}

func TestKms_CreateKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	require.NoError(t, kmsCache.CreateKeys(testCtx, "global"))
	rw := db.New(conn)

	tests := []struct {
		name            string
		kms             *kms.Kms
		scopeId         string
		opt             []kms.Option
		wantErr         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-scope-id",
			kms:             kmsCache,
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name:            "invalid-scope",
			kms:             kmsCache,
			scopeId:         "o_1234567890",
			wantErr:         true,
			wantErrContains: "violates foreign key constraint",
		},
		{
			name:            "missing-writer-opt",
			kms:             kmsCache,
			scopeId:         "global",
			opt:             []kms.Option{kms.WithReaderWriter(rw, nil)},
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing writer",
		},
		{
			name:            "missing-reader-opt",
			kms:             kmsCache,
			scopeId:         "global",
			opt:             []kms.Option{kms.WithReaderWriter(nil, rw)},
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing reader",
		},
		{
			name:    "success",
			kms:     kmsCache,
			scopeId: "global",
		},
		{
			name:    "success-with-reader-writer",
			kms:     kmsCache,
			opt:     []kms.Option{kms.WithReaderWriter(rw, rw)},
			scopeId: "global",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			kms.TestKmsDeleteAllKeys(t, conn)
			err := tc.kms.CreateKeys(testCtx, tc.scopeId, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "expected %q and got err: %+v", tc.wantErrMatch.Code, err)
				}
				if tc.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tc.wantErrContains))
				}
				return
			}
			require.NoError(err)
		})
	}
}
