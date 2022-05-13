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
	rw := db.New(conn)
	extWrapper := db.TestWrapper(t)
	badExtWrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	kmsCache := kms.TestKms(t, conn, extWrapper)
	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, extWrapper))

	// Verify that the cache is empty, so we can show that by the end of the
	// test sequence we did actually look up keys and store them in the cache
	t.Run("verify cache empty", func(t *testing.T) {
		var count int
		kmsCache.GetScopePurposeCache().Range(func(key interface{}, value interface{}) bool {
			count++
			return true
		})
		assert.Equal(t, 0, count)
	})
	// Verify that the root keys are all in the database and can be decrypted
	// with the correct wrapper from the KMS object
	t.Run("verify root keys", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rootKeys, err := repo.ListRootKeys(ctx)
		require.NoError(err)
		wrappers := kmsCache.GetExternalWrappers()
		for _, key := range rootKeys {
			kvs, err := repo.ListRootKeyVersions(ctx, wrappers.Root(), key.GetPrivateId())
			require.NoError(err)
			assert.Len(kvs, 1)
			assert.Len(kvs[0].GetKey(), 32)
		}
	})
	// Verify that the wrong wrapper causes decryption to fail
	t.Run("bad external keys", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rootKeys, err := repo.ListRootKeys(ctx)
		require.NoError(err)
		for _, key := range rootKeys {
			_, err := repo.ListRootKeyVersions(ctx, badExtWrapper, key.GetPrivateId())
			require.Error(err)
			assert.True(strings.Contains(err.Error(), "message authentication failed"), err.Error())
		}
	})
	// This next sequence is run twice to ensure that calling for the keys twice
	// returns the same value each time and doesn't simply populate more keys
	// into the KMS object
	keyBytes := map[string]bool{}
	keyIds := map[string]bool{}
	scopePurposeMap := map[string]interface{}{}
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
		// Verify that the cache has been populated with unique values. The
		// second time we validate that the items we find when going through the
		// cache a second time are the same as the first. If they were recreated
		// the pointers would be different.
		t.Run(fmt.Sprintf("verify cache populated x %d", i), func(t *testing.T) {
			var count int
			kmsCache.GetScopePurposeCache().Range(func(key interface{}, value interface{}) bool {
				count++
				if i == 1 {
					scopePurposeMap[key.(string)] = value
				} else {
					assert.Same(t, scopePurposeMap[key.(string)], value)
				}
				return true
			})
			// four purposes x 3 scopes
			assert.Equal(t, 12, count)
		})
	}
}

func TestKms_ReconcileKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
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
				db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocAuditKey(); return &i }(), "1=1")
				// make sure the kms is in the proper state for the unit test
				// before proceeding.
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
					_, err := kms.DeprecatedCreateKeysTx(context.Background(), rw, rw, wrapper, rand.Reader, id)
					require.NoError(t, err)
				}
				db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocOidcKey(); return &i }(), "1=1")
				// make sure the kms is in the proper state for the unit test
				// before proceeding.
				for _, id := range []string{org.PublicId, org2.PublicId} {
					_, err := k.GetWrapper(testCtx, id, kms.KeyPurposeAudit)
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
			db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")

			// create initial keys for the global scope...
			_, err := kms.DeprecatedCreateKeysTx(context.Background(), rw, rw, wrapper, rand.Reader, scope.Global.String())
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
