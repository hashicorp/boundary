package auth

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDB_AuthMethodIDTrigger(t *testing.T) {
	const (
		createTable = `
create table if not exists test_auth_method (
    auth_method_id wt_public_id primary key
);
`
		insert = `
insert into test_auth_method (auth_method_id)
values ($1);
`
		addTriggers = `
create trigger
  insert_auth_method_subtype
before
insert on test_auth_method
  for each row execute procedure insert_auth_method_subtype();
`
		baseTableQuery = `
select count(*) from auth_method where auth_method_id = $1;
`
		testTableQuery = `
select count(*) from test_auth_method where auth_method_id = $1;
`
	)

	assert, require := assert.New(t), require.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	db := conn.DB()
	_, err := db.Exec(createTable)
	require.NoError(err)

	_, err = db.Exec(addTriggers)
	require.NoError(err)

	id := "l1Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	_, err = db.Query(insert, id)
	require.NoError(err)

	var count int
	err = db.QueryRow(baseTableQuery, id).Scan(&count)
	require.NoError(err)
	assert.Equal(1, count)

	count = 0

	err = db.QueryRow(testTableQuery, id).Scan(&count)
	require.NoError(err)
	assert.Equal(1, count)
}

func TestDB_AuthAccountIDTrigger(t *testing.T) {
	const (
		createTable = `
create table if not exists test_auth_account (
    auth_account_id wt_public_id primary key
);
`
		insert = `
insert into test_auth_account (auth_account_id)
values ($1);
`
		addTriggers = `
create trigger
  insert_auth_account_subtype
before
insert on test_auth_account
  for each row execute procedure insert_auth_account_subtype();
`
		baseTableQuery = `
select count(*) from auth_account where auth_account_id = $1;
`
		testTableQuery = `
select count(*) from test_auth_account where auth_account_id = $1;
`
	)

	assert, require := assert.New(t), require.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	db := conn.DB()
	_, err := db.Exec(createTable)
	require.NoError(err)

	_, err = db.Exec(addTriggers)
	require.NoError(err)

	id := "l1Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	_, err = db.Query(insert, id)
	require.NoError(err)

	var count int
	err = db.QueryRow(baseTableQuery, id).Scan(&count)
	require.NoError(err)
	assert.Equal(1, count)

	count = 0

	err = db.QueryRow(testTableQuery, id).Scan(&count)
	require.NoError(err)
	assert.Equal(1, count)
}
