// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestCredentialStore(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	cs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), WithName("my-name"), WithDescription("my-description"))
	require.NotNil(cs)
	assert.NotEmpty(cs.GetPublicId())
	assert.Equal(cs.Name, "my-name")
	assert.Equal(cs.Description, "my-description")
}

func Test_TestCredentialStores(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	count := 4
	css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), count)
	assert.Len(css, count)
}

func Test_TestUsernamePasswordCredential(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	cred := TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId(), WithName("my-name"), WithDescription("my-description"))
	require.NotNil(cred)
	assert.NotEmpty(cred.GetPublicId())
	assert.Equal(cred.Name, "my-name")
	assert.Equal(cred.Description, "my-description")
	assert.Equal(cred.Username, "user")
	assert.Equal(cred.Password, []byte("pass"))

	// Validate hmac
	databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(err)
	hm, err := crypto.HmacSha256(context.Background(), cred.Password, databaseWrapper, []byte(cred.StoreId), nil, crypto.WithEd25519())
	require.NoError(err)
	assert.Equal([]byte(hm), cred.PasswordHmac)
}

func Test_TestUsernamePasswordCredentials(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	count := 4
	creds := TestUsernamePasswordCredentials(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId(), count)
	assert.Len(creds, count)
}

func Test_TestJsonCredential(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	obj, objBytes := TestJsonObject(t)

	cred := TestJsonCredential(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, WithName("my-name"), WithDescription("my-description"))
	require.NotNil(cred)
	assert.NotEmpty(cred.GetPublicId())
	assert.Equal(cred.Name, "my-name")
	assert.Equal(cred.Description, "my-description")
	assert.Equal(cred.Object, objBytes)

	// Validate hmac
	databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(err)
	hm, err := crypto.HmacSha256(context.Background(), cred.Object, databaseWrapper, []byte(cred.StoreId), nil)
	require.NoError(err)
	assert.Equal([]byte(hm), cred.ObjectHmac)
}

func Test_TestJsonCredentials(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	obj, _ := TestJsonObject(t)

	count := 3
	creds := TestJsonCredentials(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, count)
	assert.Len(creds, count)
}
