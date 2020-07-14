package auth

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDB_AuthMethodIDTrigger(t *testing.T) {
	const (
		createTable = `
create table if not exists test_auth_method (
    public_id wt_public_id primary key,
    scope_id wt_public_id not null references iam_scope(public_id)
);
`
		insert = `
insert into test_auth_method
  (public_id, scope_id)
values
  ($1, $2);
`
		addTriggers = `
create trigger
  insert_auth_method_subtype
before
insert on test_auth_method
  for each row execute procedure insert_auth_method_subtype();
`
		baseTableQuery = `
select count(*) from auth_method where public_id = $1;
`
		testTableQuery = `
select count(*) from test_auth_method where public_id = $1;
`
	)

	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	db := conn.DB()
	_, err := db.Exec(createTable)
	require.NoError(err)

	_, err = db.Exec(addTriggers)
	require.NoError(err)

	org, _ := iam.TestScopes(t, conn)

	id := "l1Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	_, err = db.Query(insert, id, org.GetPublicId())
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
    public_id wt_public_id primary key,
    auth_method_id wt_public_id not null,
    scope_id wt_public_id not null
);
`
		insert = `
insert into test_auth_account
  (public_id, auth_method_id, scope_id)
values
  ($1, $2, $3);
`
		addTriggers = `
create trigger
  insert_auth_account_subtype
before
insert on test_auth_account
  for each row execute procedure insert_auth_account_subtype();
`
		baseTableQuery = `
select count(*) from auth_account where public_id = $1;
`
		testTableQuery = `
select count(*) from test_auth_account where public_id = $1;
`
		insertAuthMethod = `
insert into auth_method
  (public_id, scope_id)
values
  ($1, $2);
`
	)

	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	db := conn.DB()
	_, err := db.Exec(createTable)
	require.NoError(err)

	_, err = db.Exec(addTriggers)
	require.NoError(err)

	org, _ := iam.TestScopes(t, conn)
	meth_id := "31Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	_, err = db.Query(insertAuthMethod, meth_id, org.GetPublicId())
	require.NoError(err)

	id := "l1Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	_, err = db.Query(insert, id, meth_id, org.GetPublicId())
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
