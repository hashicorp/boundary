package password

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthMethod creates a password auth methods to the provided DB with the
// provided scope id. If any errors are encountered during the creation of the
// auth methods, the test will fail.
func TestAuthMethod(t testing.TB, conn *db.DB, scopeId string, opt ...Option) *AuthMethod {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	cat, err := NewAuthMethod(scopeId, opt...)
	assert.NoError(err)
	require.NotNil(cat)
	id, err := newAuthMethodId()
	assert.NoError(err)
	require.NotEmpty(id)
	cat.PublicId = id

	conf := NewArgon2Configuration()
	require.NotNil(conf)
	conf.PrivateId, err = newArgon2ConfigurationId()
	require.NoError(err)
	conf.PasswordMethodId = cat.PublicId
	cat.PasswordConfId = conf.PrivateId

	ctx := context.Background()
	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(iw.Create(ctx, conf))
			return iw.Create(ctx, cat)
		},
	)

	require.NoError(err2)
	return cat
}

// TestAuthMethods creates count number of password auth methods to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the auth methods, the test will fail.
func TestAuthMethods(t testing.TB, conn *db.DB, scopeId string, count int) []*AuthMethod {
	t.Helper()
	var auts []*AuthMethod
	for i := 0; i < count; i++ {
		auts = append(auts, TestAuthMethod(t, conn, scopeId))
	}
	return auts
}

// TestMultipleAccounts creates count number of password account to the provided DB
// with the provided auth method id.  The auth method must have been created previously.
// If any errors are encountered during the creation of the account, the test will fail.
func TestMultipleAccounts(t testing.TB, conn *db.DB, authMethodId string, count int) []*Account {
	t.Helper()
	var auts []*Account
	for i := 0; i < count; i++ {
		auts = append(auts, TestAccount(t, conn, authMethodId, fmt.Sprintf("name%d", i)))
	}
	return auts
}

// TestAccount creates a password account to the provided DB with the provided
// auth method id and loginName.  The auth method must have been created
// previously. See password.NewAccount(...) for a list of supported options.
// If any errors are encountered during the creation of the account, the test will fail.
func TestAccount(t testing.TB, conn *db.DB, authMethodId, loginName string, opt ...Option) *Account {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	require.NotEmpty(loginName)
	w := db.New(conn)
	opt = append(opt, WithLoginName(loginName))
	cat, err := NewAccount(authMethodId, opt...)
	assert.NoError(err)
	require.NotNil(cat)
	id, err := newAccountId()
	assert.NoError(err)
	require.NotEmpty(id)
	cat.PublicId = id

	ctx := context.Background()
	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			return iw.Create(ctx, cat)
		},
	)
	require.NoError(err2)
	return cat
}
