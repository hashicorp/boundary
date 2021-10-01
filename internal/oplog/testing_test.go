package oplog

import (
	"context"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_testCleanup(t *testing.T) {
	assert := assert.New(t)
	cleanup, db := setup(t)
	testCleanup(t, cleanup, db)

	err := db.Begin().Error
	assert.Equal("sql: database is closed", err.Error())
}

func Test_testUser(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	id := testId(t)

	u := testUser(t, db, id, id, id)
	require.NotNil(u)
	assert.Equal(id, u.Name)
	assert.Equal(id, u.PhoneNumber)
	assert.Equal(id, u.Email)
}

func Test_testFindUser(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	id := testId(t)
	u := testUser(t, db, id, id, id)
	require.NotNil(u)

	found := testFindUser(t, db, u.Id)
	require.NotNil(found)
	assert.Equal(u, found)
}

func Test_testId(t *testing.T) {
	require := require.New(t)
	id := testId(t)
	require.NotNil(id)
}

func Test_testInitDbInDocker(t *testing.T) {
	require := require.New(t)
	cleanup, url, err := testInitDbInDocker(t)
	defer cleanup()
	require.NoError(err)
	require.NotEmpty(url)
	require.NotNil(cleanup)
}

func Test_testWrapper(t *testing.T) {
	w := testWrapper(t)
	require.NotNil(t, w)
	typ, err := w.Type(context.Background())
	require.NoError(t, err)
	assert.Equal(t, wrapping.WrapperTypeAead, typ)
}

func Test_testInitStore(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	cleanup, url, err := testInitDbInDocker(t)
	require.NoError(err)
	defer cleanup()
	require.NotEmpty(url)

	testInitStore(t, cleanup, url)

	const query = `
select count(*) from information_schema."tables" t where table_name = 'db_test_user';
`
	db, err := common.SqlOpen("postgres", url)
	require.NoError(err)

	var cnt int
	err = db.QueryRow(query).Scan(&cnt)
	require.NoError(err)
	assert.Equal(1, cnt)
}
