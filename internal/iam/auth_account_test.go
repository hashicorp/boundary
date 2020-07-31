package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	dbassert "github.com/hashicorp/watchtower/internal/db/assert"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// this is a very limited test.  we are not testing the auth account triggers
// and integrity checks (we will leave that to the auth subsystem, since that's
// where they are implemented). we just want to make sure that the iam subsystem
// can update the IamUserId field successfully since that's what the iam system
// relies on.
func Test_AccountUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	rw := db.New(conn)
	t.Run("simple-update", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		u := TestUser(t, conn, org.PublicId)
		authMethodPublicId := testAuthMethod(t, conn, org.PublicId)
		acct := testAccount(t, conn, org.PublicId, authMethodPublicId, "")

		updateAcct := acct.Clone().(*Account)
		updateAcct.IamUserId = u.PublicId
		updatedRows, err := rw.Update(context.Background(), updateAcct, []string{"IamUserId"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)

		foundAcct := allocAccount()
		foundAcct.PublicId = acct.PublicId
		err = rw.LookupByPublicId(context.Background(), &foundAcct)
		require.NoError(err)
		assert.Equal(u.PublicId, foundAcct.IamUserId)
	})
}

func TestAccount_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)

	t.Run("valid-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		u := TestUser(t, conn, org.PublicId)
		authMethodPublicId := testAuthMethod(t, conn, org.PublicId)
		acct := testAccount(t, conn, org.PublicId, authMethodPublicId, u.PublicId)
		scope, err := acct.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(org, scope))
	})
}

func TestAccount_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		u := TestUser(t, conn, org.PublicId)
		authMethodPublicId := testAuthMethod(t, conn, org.PublicId)
		acct := testAccount(t, conn, org.PublicId, authMethodPublicId, u.PublicId)
		cp := acct.Clone()
		assert.True(proto.Equal(cp.(*Account).Account, acct.Account))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		rw := db.New(conn)
		u := TestUser(t, conn, org.PublicId)
		authMethodPublicId := testAuthMethod(t, conn, org.PublicId)
		acct := testAccount(t, conn, org.PublicId, authMethodPublicId, u.PublicId)
		acct2 := testAccount(t, conn, org.PublicId, authMethodPublicId, "")
		dbassert := dbassert.New(t, rw)
		dbassert.IsNull(acct2, "IamUserId")
		cp := acct.Clone()
		assert.True(!proto.Equal(cp.(*Account).Account, acct2.Account))
	})
}

func TestAccount_SetTableName(t *testing.T) {
	defaultTableName := defaultAccountTableName
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &Account{
				Account: &store.Account{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &Account{
				Account:   &store.Account{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
