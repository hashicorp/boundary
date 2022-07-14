package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialStore creates a static credential store in the provided DB with
// the provided scope and any values passed in through the Options vars.
// If any errors are encountered during the creation of the store, the test will fail.
func TestCredentialStore(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, scopeId string, opt ...Option) *CredentialStore {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cs, err := NewCredentialStore(scopeId, opt...)
	assert.NoError(t, err)
	require.NotNil(t, cs)

	opts := getOpts(opt...)
	id := opts.withPublicId
	if id == "" {
		id, err = newCredentialStoreId(ctx)
		assert.NoError(t, err)
		require.NotEmpty(t, id)
	}
	cs.PublicId = id

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cs))
			return nil
		},
	)
	require.NoError(t, err2)

	return cs
}

// TestCredentialStores creates count number of static credential stores in
// the provided DB with the provided scope id. If any errors are
// encountered during the creation of the credential stores, the test will
// fail.
func TestCredentialStores(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, scopeId string, count int) []*CredentialStore {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	css := make([]*CredentialStore, 0, count)
	for i := 0; i < count; i++ {
		css = append(css, TestCredentialStore(t, conn, wrapper, scopeId))
	}
	return css
}

// TestUsernamePasswordCredential creates a username password credential in the provided DB with
// the provided scope and any values passed in through.
// If any errors are encountered during the creation of the store, the test will fail.
func TestUsernamePasswordCredential(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, password, storeId, scopeId string,
	opt ...Option,
) *UsernamePasswordCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	opts := getOpts(opt...)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cred, err := NewUsernamePasswordCredential(storeId, username, credential.Password(password), opt...)
	require.NoError(t, err)
	require.NotNil(t, cred)

	id := opts.withPublicId
	if id == "" {
		id, err = credential.NewUsernamePasswordCredentialId(ctx)
		require.NoError(t, err)
	}
	cred.PublicId = id

	err = cred.encrypt(ctx, databaseWrapper)
	require.NoError(t, err)

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cred))
			return nil
		},
	)
	require.NoError(t, err2)

	return cred
}

// TestUsernamePasswordCredentials creates count number of username password credentials in
// the provided DB with the provided scope id. If any errors are
// encountered during the creation of the credentials, the test will fail.
func TestUsernamePasswordCredentials(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, password, storeId, scopeId string,
	count int,
) []*UsernamePasswordCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	creds := make([]*UsernamePasswordCredential, 0, count)
	for i := 0; i < count; i++ {
		creds = append(creds, TestUsernamePasswordCredential(t, conn, wrapper, username, password, storeId, scopeId))
	}
	return creds
}
