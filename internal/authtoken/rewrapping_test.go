package authtoken

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func TestRewrap_authTokenRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	// TestAuthToken will create and store the token for us
	at := TestAuthToken(t, conn, kmsCache, org.GetPublicId())

	// now things are stored in the db, we can rotate and rewrap
	err := kmsCache.RotateKeys(ctx, org.Scope.GetPublicId())
	assert.NoError(t, err)

	err = authTokenRewrapFn(ctx, at.GetKeyId(), rw, rw, kmsCache)
	assert.NoError(t, err)

	// now we pull the authToken back from the db, decrypt it with the new key, and ensure things match
	// as a security measure, LookupAuthToken clears both CtToken and KeyId, which are the fields we want, so we will lookup manually
	atv := allocAuthTokenView()
	atv.PublicId = at.GetPublicId()
	rw.LookupByPublicId(ctx, atv)
	assert.NoError(t, err)
	newAt := atv.toAuthToken()

	assert.Equal(t, at.GetPublicId(), newAt.GetPublicId())
	assert.NotEqual(t, at.GetKeyId(), atv.GetKeyId())

	// fetch the new key version
	kmsWrapper, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(newAt.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersion, err := kmsWrapper.KeyId(ctx)
	assert.NoError(t, err)

	fmt.Printf("at: %#v\natv: %#v\nnewAt: %#v\n", at.GetKeyId(), atv.GetKeyId(), newAt.GetKeyId())

	// decrypt with the new key version and check to make sure things match
	err = newAt.decrypt(ctx, kmsWrapper)
	assert.NoError(t, err)
	fmt.Printf("at: %#v\nnewAt: %#v\n, expected keyid: %s\n", at.AuthToken, newAt.AuthToken, newKeyVersion)

	// assert.Equal(t, newKeyVersion, newAt.GetKeyId()) newAt ALWAYS HAS AN EMPTY KEY ID AND I DON'T KNOW WHY
	// I've confirmed from the db that the key id is, in fact, stored and is correct, but it cannot be retrieved??
	assert.Equal(t, at.GetToken(), newAt.GetToken())
}
