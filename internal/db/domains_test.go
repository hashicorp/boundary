package db

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-sql/civil"
	_ "github.com/jackc/pgx/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomain_Ids(t *testing.T) {
	const (
		createTableBase = `
create table if not exists test_table_{{rep}}_id (
  id bigint generated always as identity primary key,
  {{rep}}_id wt_{{rep}}_id
);
`
		insertBase = `
insert into test_table_{{rep}}_id ({{rep}}_id)
values ($1)
returning id;
`
	)

	conn, _ := TestSetup(t, "postgres")
	db := conn.DB()

	for _, typ := range []string{"public", "private", "role", "scope"} {
		createTable := strings.Replace(createTableBase, "{{rep}}", typ, -1)
		insert := strings.Replace(insertBase, "{{rep}}", typ, -1)

		if _, err := db.Exec(createTable); err != nil {
			t.Fatalf("query: \n%s\n error: %s", createTable, err)
		}

		failTests := []struct {
			value     string
			exception string
		}{
			{
				" ",
				"",
			},
			{
				"bar",
				"",
			},
			{
				"00000009",
				"",
			},
			{
				"r_default",
				"role",
			},
			{
				"global",
				"scope",
			},
		}
		for _, tt := range failTests {
			t.Run(tt.value, func(t *testing.T) {
				t.Logf("insert value: %q", tt.value)
				_, err := db.Query(insert, tt.value)
				switch {
				case err == nil && tt.exception != typ:
					t.Errorf("want error, got no error for inserting public_id: %s", tt.value)
				case err == nil && tt.exception == typ:
					// All good
				case err != nil && tt.exception != typ:
					// All good
				default:
					t.Fatal("unhandled")
				}
			})
		}

		okTests := []string{
			"l1Ocw0TpHn800CekIxIXlmQqRDgFDfYl",
			"00000000010000000002000000000312",
			"00000000010000000002000000000032",
			"12345678901234567890123456789012",
			"ec2_12345678901234567890123456789012",
			"prj_12345678901234567890123456789012",
		}
		for _, tt := range okTests {
			value := tt
			t.Run(tt, func(t *testing.T) {
				t.Logf("insert value: %q", value)
				if _, err := db.Query(insert, value); err != nil {
					t.Errorf("%s: want no error, got error %v", value, err)
				}
			})
		}
	}
}

func TestDomain_Timestamp(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_timestamp (
  id bigint generated always as identity primary key,
  name text,
  good_time wt_timestamp,
  bad_time timestamp default current_timestamp
);
`
		insert = `
insert into test_table_timestamp (name)
values ($1)
returning id;
`
	)

	conn, _ := TestSetup(t, "postgres")
	db := conn.DB()
	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	if _, err := db.Exec(insert, "foo"); err != nil {
		t.Fatalf("want no error, got error %v", err)
	}

	if _, err := db.Query("select extract(timezone from good_time) from test_table_timestamp;"); err != nil {
		t.Errorf("want no error, got error %v", err)
	}

	if _, err := db.Query("select extract(timezone from bad_time) from test_table_timestamp;"); err == nil {
		t.Errorf("want error, got no error")
	}
}

func TestDomain_immutable_create_time_func(t *testing.T) {
	assert := assert.New(t)

	const (
		createTable = `
create table if not exists test_immutable_create_time (
  id bigint generated always as identity primary key,
  name text,
  create_time wt_timestamp
);
`
		addTriggers = `
create trigger
  test_update_immutable_create_time
before
update on test_immutable_create_time
  for each row execute procedure immutable_create_time_func();
`
		query = `
select create_time from test_immutable_create_time where id = $1
`
		countQuery = `
select count(*) from test_immutable_create_time
`
		insert = `
insert into test_immutable_create_time (name)
values ('alice')
returning id;
`
		// no where clause intentionally, since it's not needed for the test
		update = `
update test_immutable_create_time
set name = 'bob';
`

		// no where clause intentionally, since it's not needed for the test
		bad_update = `
update test_immutable_create_time
set create_time = now();
`
		// no where clause intentionally, since it's not needed for the test
		bad_update_null = `
update test_immutable_create_time
set create_time = null;
`
	)

	conn, _ := TestSetup(t, "postgres")
	db := conn.DB()
	_, err := db.Exec(createTable)
	assert.NoError(err)

	_, err = db.Exec(addTriggers)
	assert.NoError(err)

	var id int
	err = db.QueryRow(insert).Scan(&id)
	assert.NoError(err)

	var origTime time.Time
	err = db.QueryRow(query, id).Scan(&origTime)
	assert.NoError(err)

	var count int
	err = db.QueryRow(countQuery).Scan(&count)
	assert.NoError(err)
	assert.Equal(1, count)

	_, err = db.Exec(update)
	assert.NoError(err)

	_, err = db.Exec(bad_update)
	assert.NoError(err)

	var updateTime time.Time
	err = db.QueryRow(query, id).Scan(&updateTime)
	assert.NoError(err)
	assert.Equal(origTime, updateTime)

	_, err = db.Exec(bad_update_null)
	assert.NoError(err)

	err = db.QueryRow(query, id).Scan(&updateTime)
	assert.NoError(err)
	assert.Equal(origTime, updateTime)

}

func TestDomain_update_time_column(t *testing.T) {
	assert := assert.New(t)

	const (
		createTable = `
create table if not exists test_update_time_column (
  id bigint generated always as identity primary key,
  name text,
  update_time wt_timestamp
);
`
		addTriggers = `
create trigger
  test_update_time_column
before
update on test_update_time_column
  for each row execute procedure update_time_column();
`
		countQuery = `
select count(*) from test_update_time_column
`
		query = `
select update_time from test_update_time_column where id = $1
`
		insert = `
insert into test_update_time_column (name)
values ('bob')
returning id;
`
		// no where clause intentionally, since it's not needed for the test
		update = `
update test_update_time_column
set name = 'alice';
`

		// no where clause intentionally, since it's not needed for the test
		bad_update = `
update test_update_time_column
set update_time = now() - interval '3 days';
`
		// no where clause intentionally, since it's not needed for the test
		bad_update_null = `
update test_update_time_column
set update_time = null;
`
	)

	conn, _ := TestSetup(t, "postgres")
	db := conn.DB()
	_, err := db.Exec(createTable)
	assert.NoError(err)

	_, err = db.Exec(addTriggers)
	assert.NoError(err)

	var id int
	err = db.QueryRow(insert).Scan(&id)
	assert.NoError(err)

	var origTime time.Time
	err = db.QueryRow(query, id).Scan(&origTime)
	assert.NoError(err)
	orig := civil.DateTimeOf(origTime)

	var count int
	err = db.QueryRow(countQuery).Scan(&count)
	assert.NoError(err)
	assert.Equal(1, count)

	_, err = db.Exec(update)
	assert.NoError(err)

	_, err = db.Exec(bad_update)
	assert.NoError(err)

	var updateTime time.Time
	err = db.QueryRow(query, id).Scan(&updateTime)
	assert.NoError(err)
	updated := civil.DateTimeOf(updateTime)
	assert.True(updated.After(orig))

	_, err = db.Exec(bad_update_null)
	assert.NoError(err)

	var nextUpdateTime time.Time
	err = db.QueryRow(query, id).Scan(&nextUpdateTime)
	assert.NoError(err)
	nextUpdated := civil.DateTimeOf(nextUpdateTime)
	assert.True(nextUpdated.After(updated))
}

func TestDomain_wt_version(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_version(
	public_id bigint generated always as identity primary key,
	name text,
	version wt_version
);
`
		addTrigger = `
create trigger 
  update_version_column
after update on test_table_wt_version
  for each row execute procedure update_version_column();
`
		insert = `
insert into test_table_wt_version (name)
values ($1)
returning public_id;
`
		update = `update test_table_wt_version set name = $1 where public_id = $2;`

		updateVersion = `update test_table_wt_version set version = $1 where public_id = $2;`

		search = `select version from test_table_wt_version where public_id = $1`
	)
	conn, _ := TestSetup(t, "postgres")
	assert, require := assert.New(t), require.New(t)

	db := conn.DB()
	_, err := db.Exec(createTable)
	require.NoError(err)

	_, err = db.Exec(addTrigger)
	require.NoError(err)

	var id int
	err = db.QueryRow(insert, "alice").Scan(&id)
	require.NoError(err)
	require.NotEmpty(id)

	var v int
	err = db.QueryRow(search, id).Scan(&v)
	require.NoError(err)
	assert.Equal(1, v)

	_, err = db.Exec(update, "bob", id)
	require.NoError(err)
	err = db.QueryRow(search, id).Scan(&v)
	require.NoError(err)
	assert.Equal(2, v)

	_, err = db.Exec(updateVersion, 22, id)
	require.NoError(err)
	err = db.QueryRow(search, id).Scan(&v)
	require.NoError(err)
	assert.Equal(3, v)
}

func TestDomain_DisallowDefaultRoleModification(t *testing.T) {
	conn, _ := TestSetup(t, "postgres")
	db := conn.DB()

	_, err := db.Exec(`delete from iam_role where public_id = $1`, "r_default")
	require.Error(t, err)
	assert.Equal(t, `pq: deletion of default role not allowed`, err.Error())

	// This actually tests not just default, but all roles
	_, err = db.Exec(`update iam_role set public_id = $1 where public_id = $2`, "r_something", "r_default")
	require.Error(t, err)
	assert.Equal(t, `pq: update of role primary key not allowed`, err.Error())
}

func TestDomain_DefaultUsersExist(t *testing.T) {
	conn, _ := TestSetup(t, "postgres")
	db := conn.DB()

	for _, val := range []string{"u_anon", "u_auth"} {
		rows, err := db.Query(`select from iam_user where public_id = $1`, val)
		require.NoError(t, err)
		var count int
		for rows.Next() {
			count++
		}
		assert.Equal(t, 1, count)
	}
}
