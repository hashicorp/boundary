package password

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMethods(t *testing.T, conn *gorm.DB, scopeId string, count int) []*AuthMethod {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var auts []*AuthMethod
	for i := 0; i < count; i++ {
		cat, err := NewAuthMethod(scopeId)
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
		auts = append(auts, cat)
	}
	return auts
}

func TestAccounts(t *testing.T, conn *gorm.DB, scopeId, authMethodId string, count int) []*Account {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var auts []*Account
	for i := 0; i < count; i++ {
		cat, err := NewAccount(authMethodId, fmt.Sprintf("name%d", i))
		assert.NoError(err)
		require.NotNil(cat)
		id, err := newAccountId()
		assert.NoError(err)
		require.NotEmpty(id)
		cat.PublicId = id
		require.NoError(w.Create(context.Background(), cat))
		// TODO(toddknight): Figure out why the iw.Create call doesn't populate the scope id from the DB.
		cat.ScopeId = scopeId
		auts = append(auts, cat)
	}
	return auts
}
