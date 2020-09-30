package auth

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
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

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	_, err := rw.Exec(ctx, createTable, nil)
	require.NoError(err)

	_, err = rw.Exec(ctx, addTriggers, nil)
	require.NoError(err)

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	id := "l1Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	inserted, err := rw.Exec(ctx, insert, []interface{}{id, org.GetPublicId()})
	require.NoError(err)
	require.Equal(1, inserted)

	type c struct {
		Count int
	}
	var count c
	rows, err := rw.Query(ctx, baseTableQuery, []interface{}{id})
	require.NoError(err)
	defer rows.Close()
	for rows.Next() {
		err := rw.ScanRows(rows, &count)
		require.NoError(err)
	}
	assert.Equal(1, count.Count)

	count.Count = 0
	rows, err = rw.Query(ctx, testTableQuery, []interface{}{id})
	require.NoError(err)
	defer rows.Close()
	for rows.Next() {
		err := rw.ScanRows(rows, &count)
		require.NoError(err)
	}
	assert.Equal(1, count.Count)
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
  (public_id, auth_method_id)
values
  ($1, $2);
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

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	_, err := rw.Exec(ctx, createTable, nil)
	require.NoError(err)

	_, err = rw.Exec(ctx, addTriggers, nil)
	require.NoError(err)

	org, _ := iam.TestScopes(t, repo)
	meth_id := "31Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	_, err = rw.Exec(ctx, insertAuthMethod, []interface{}{meth_id, org.GetPublicId()})
	require.NoError(err)

	id := "l1Ocw0TpHn800CekIxIXlmQqRDgFDfYl"
	_, err = rw.Exec(ctx, insert, []interface{}{id, meth_id})
	require.NoError(err)

	type c struct {
		Count int
	}
	var count c
	rows, err := rw.Query(ctx, baseTableQuery, []interface{}{id})
	require.NoError(err)
	defer rows.Close()
	for rows.Next() {
		err := rw.ScanRows(rows, &count)
		require.NoError(err)
	}
	assert.Equal(1, count.Count)

	count.Count = 0
	rows, err = rw.Query(ctx, testTableQuery, []interface{}{id})
	require.NoError(err)
	defer rows.Close()
	for rows.Next() {
		err := rw.ScanRows(rows, &count)
		require.NoError(err)
	}
	assert.Equal(1, count.Count)
}
