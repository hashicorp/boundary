package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialStores creates count number of vault credential stores in
// the provided DB with the provided scope id. If any errors are
// encountered during the creation of the credential stores, the test will
// fail.
func TestCredentialStores(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, scopeId string, count int) []*CredentialStore {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var css []*CredentialStore
	for i := 0; i < count; i++ {

		cs, err := NewCredentialStore(scopeId, fmt.Sprintf("http://vault%d", i), []byte(fmt.Sprintf("token%d", i)))
		assert.NoError(err)
		require.NotNil(cs)
		id, err := newCredentialStoreId()
		assert.NoError(err)
		require.NotEmpty(id)
		cs.PublicId = id

		ctx := context.Background()
		_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, cs)
			},
		)

		require.NoError(err2)
		css = append(css, cs)
	}
	return css
}

// TestCredentialLibraries creates count number of vault credential
// libraries in the provided DB with the provided store id. If any errors
// are encountered during the creation of the credential libraries, the
// test will fail.
func TestCredentialLibraries(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, storeId string, count int) []*CredentialLibrary {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var libs []*CredentialLibrary

	for i := 0; i < count; i++ {
		lib, err := NewCredentialLibrary(storeId, fmt.Sprintf("vault/path%d", i))
		assert.NoError(err)
		require.NotNil(lib)
		id, err := newCredentialLibraryId()
		assert.NoError(err)
		require.NotEmpty(id)
		lib.PublicId = id

		ctx := context.Background()
		_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, lib)
			},
		)

		require.NoError(err2)
		libs = append(libs, lib)
	}
	return libs
}

func testTokens(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, scopeId, storeId string, count int) []*Token {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)

	ctx := context.Background()
	kkms := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kkms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(err)
	require.NotNil(databaseWrapper)

	var tokens []*Token
	for i := 0; i < count; i++ {
		inToken, err := newToken(storeId, []byte(fmt.Sprintf("vault-token-%d", i)), 5*time.Minute)
		assert.NoError(err)
		require.NotNil(inToken)

		if i > 0 {
			// only one 'current' token is allowed
			// mark additional tokens as maintaining
			inToken.Status = string(StatusMaintaining)
		}

		require.NoError(inToken.encrypt(ctx, databaseWrapper))
		query, queryValues := inToken.insertQuery()

		rows, err2 := w.Exec(ctx, query, queryValues)
		assert.Equal(1, rows)
		require.NoError(err2)

		outToken := allocToken()
		require.NoError(w.LookupWhere(ctx, &outToken, "token_sha256 = ?", inToken.TokenSha256))
		require.NoError(outToken.decrypt(ctx, databaseWrapper))

		tokens = append(tokens, outToken)
	}
	return tokens
}
