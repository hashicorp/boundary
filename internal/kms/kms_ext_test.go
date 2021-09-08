package kms_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/multiwrapper"
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
					multi, ok := wrapper.(*multiwrapper.MultiWrapper)
					require.True(ok)
					aeadWrapper, ok := multi.WrapperForKeyID(multi.KeyID()).(*aead.Wrapper)
					require.True(ok)
					foundKeyBytes := keyBytes[base64.StdEncoding.EncodeToString(aeadWrapper.GetKeyBytes())]
					foundKeyId := keyIds[aeadWrapper.KeyID()]
					if i == 1 {
						assert.False(foundKeyBytes)
						assert.False(foundKeyId)
						keyBytes[base64.StdEncoding.EncodeToString(aeadWrapper.GetKeyBytes())] = true
						keyIds[aeadWrapper.KeyID()] = true
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
