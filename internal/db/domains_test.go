// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-sql/civil"
	"github.com/hashicorp/boundary/globals"
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

	ctx := context.Background()

	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

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

func TestDomain_TagPairs(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table (
  pair wt_tagpair primary key
);
`
		insert = `
insert into test_table
values ($1);
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	tests := []struct {
		value string
		fail  bool
	}{
		{
			" ",
			true,
		},
		{
			"00000009",
			false,
		},
		{
			"ABC123",
			true,
		},
		{
			"092h3oiuansdfh98wh3piornasiopudhfp98aw384rhfaouisdhnfios",
			false,
		},
		{
			strings.Repeat("1234567890", 51),
			false,
		},
		{
			strings.Repeat("1234567890", 52),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			// t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			switch {
			case err == nil && tt.fail:
				t.Errorf("want error, got no error for inserting value: %s", tt.value)
			case err == nil && !tt.fail:
				// All good
			case err != nil && tt.fail:
				// All good
			default:
				t.Errorf("expected no error, got error: %s", err)
			}
		})
	}
	t.Run("null", func(t *testing.T) {
		_, err := db.Query("insert into test_table values (null);")
		assert.Contains(t, err.Error(), "violates check constraint")
	})
}

func TestDomain_Bexprfilter(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table (
  filter wt_bexprfilter
);
`
		insert = `
insert into test_table
values ($1);
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	tests := []struct {
		value string
		fail  bool
	}{
		{
			" ",
			true,
		},
		{
			"00000009",
			false,
		},
		{
			"ABC123",
			false,
		},
		{
			`"/foo/bar" in "/values"`,
			false,
		},
		{
			strings.Repeat("1234567890", 204),
			false,
		},
		{
			strings.Repeat("1234567890", 205),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			// t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			switch {
			case err == nil && tt.fail:
				t.Errorf("want error, got no error for inserting value: %s", tt.value)
			case err == nil && !tt.fail:
				// All good
			case err != nil && tt.fail:
				// All good
			default:
				t.Errorf("expected no error, got error: %s", err)
			}
		})
	}
	t.Run("null", func(t *testing.T) {
		_, err := db.Query("insert into test_table values (null);")
		assert.NoError(t, err)
	})
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

	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)
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
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	_, err = db.Exec(createTable)
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
	ctx := context.Background()
	db, err := conn.SqlDB(ctx)
	require.NoError(err)

	_, err = db.Exec(createTable)
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

func TestDomain_wt_version_with_private_id(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_version(
	private_id bigint generated always as identity primary key,
	name text,
	version wt_version
);
`
		addTrigger = `
create trigger 
  update_version_column
after update on test_table_wt_version
  for each row execute procedure update_version_column('private_id');
`
		insert = `
insert into test_table_wt_version (name)
values ($1)
returning private_id;
`
		update = `update test_table_wt_version set name = $1 where private_id = $2;`

		updateVersion = `update test_table_wt_version set version = $1 where private_id = $2;`

		search = `select version from test_table_wt_version where private_id = $1`
	)
	conn, _ := TestSetup(t, "postgres")
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	db, err := conn.SqlDB(ctx)
	require.NoError(err)

	_, err = db.Exec(createTable)
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

func TestDomain_DefaultUsersExist(t *testing.T) {
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	for _, val := range []string{globals.AnonymousUserId, globals.AnyAuthenticatedUserId} {
		rows, err := db.Query(`select from iam_user where public_id = $1`, val)
		require.NoError(t, err)
		var count int
		for rows.Next() {
			count++
		}
		assert.NoError(t, rows.Err())
		assert.Equal(t, 1, count)
	}
}

func TestDomain_immutable_columns_func(t *testing.T) {
	const (
		createTable = `
create table if not exists test_immutable_columns (
  id bigint generated always as identity primary key,
  name text not null,
  create_time wt_timestamp not null,
  updatable text not null
);
`
		addTriggers = `
create trigger
  test_update_immutable_columns
before
update on test_immutable_columns
  for each row execute procedure immutable_columns('id', 'name', 'create_time');
`
		dropTriggers = `drop trigger test_update_immutable_columns on test_immutable_columns`

		addBadTriggers = `
create trigger
  test_update_bad_immutable_columns
before
update on test_immutable_columns
  for each row execute procedure immutable_columns('id', 'bad_column_name', 'create_time');
`
		dropBadTriggers = `drop trigger test_update_bad_immutable_columns on test_immutable_columns`

		query = `
select id, name, create_time, updatable from test_immutable_columns where id = $1
`
		countQuery = `
select count(*) from test_immutable_columns
`
		insert = `
insert into test_immutable_columns (name, updatable)
values ('alice', 'update alice')
returning id;
`
		// no where clause intentionally, since it's not needed for the test
		update_updatable = `
update test_immutable_columns
set updatable = 'updated bob';
`

		// no where clause intentionally, since it's not needed for the test
		bad_update_create_time = `
update test_immutable_columns
set create_time = now();
`
		// no where clause intentionally, since it's not needed for the test
		bad_update_null_create_time = `
update test_immutable_columns
set create_time = null;
`

		// no where clause intentionally, since it's not needed for the test
		bad_update_id = `
update test_immutable_columns
set id = 22;
`
		// no where clause intentionally, since it's not needed for the test
		bad_update_null_id = `
update test_immutable_columns
set id = null;
`
	)

	type rowData struct {
		Id         int
		CreateTime time.Time
		Name       string
		Updatable  string
	}
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	_, err = db.Exec(createTable)
	assert.NoError(t, err)

	_, err = db.Exec(addTriggers)
	assert.NoError(t, err)

	var id int
	err = db.QueryRow(insert).Scan(&id)
	assert.NoError(t, err)

	var orig rowData
	err = db.QueryRow(query, id).Scan(&orig.Id, &orig.Name, &orig.CreateTime, &orig.Updatable)
	assert.NoError(t, err)

	var count int
	err = db.QueryRow(countQuery).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)

	tests := []struct {
		name string
		stmt string
	}{
		{
			name: "update create time",
			stmt: bad_update_create_time,
		},
		{
			name: "null create time",
			stmt: bad_update_null_create_time,
		},
		{
			name: "update id",
			stmt: bad_update_id,
		},
		{
			name: "null id",
			stmt: bad_update_null_id,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			_, err = db.Exec(tt.stmt)
			assert.Error(err)

			var found rowData
			err = db.QueryRow(query, id).Scan(&found.Id, &found.Name, &found.CreateTime, &found.Updatable)
			assert.NoError(err)
			assert.Equal(orig.Id, found.Id)
			assert.Equal(orig.Name, found.Name)
			assert.Equal(orig.CreateTime, found.CreateTime)
		})
	}
	t.Run("updatable", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err = db.Exec(update_updatable)
		require.NoError(err)
		var found rowData
		err = db.QueryRow(query, id).Scan(&found.Id, &found.Name, &found.CreateTime, &found.Updatable)
		require.NoError(err)
		assert.NotEqual(orig.Updatable, found.Updatable)
	})

	t.Run("bad column", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		t.Cleanup(func() {
			// reset the update trigger to what they were before this test
			// started.
			_, err = db.Exec(dropBadTriggers)
			require.NoError(err)

			_, err = db.Exec(addTriggers)
			assert.NoError(err)
		})
		_, err = db.Exec(dropTriggers)
		require.NoError(err)

		_, err = db.Exec(addBadTriggers)
		require.NoError(err)

		_, err = db.Exec(update_updatable)
		require.Error(err)
		assert.Containsf(err.Error(), `SQLSTATE 42703`, "unexpected error msg: %s", err.Error())

		var found rowData
		err = db.QueryRow(query, id).Scan(&found.Id, &found.Name, &found.CreateTime, &found.Updatable)
		assert.NoError(err)
		assert.Equal(orig.Id, found.Id)
		assert.Equal(orig.Name, found.Name)
		assert.Equal(orig.CreateTime, found.CreateTime)
	})
}

func TestDomain_wt_url(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_url (
  id bigint generated always as identity primary key,
  url wt_url
);
`
		insert = `
insert into test_table_wt_url(url)
values ($1)
returning id;
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	failTests := []struct {
		value     string
		exception string
	}{
		{"http://", ""},
		{"htt://", "wt_url_invalid_protocol"},
		{"ht", "wt_url_invalid_protocol"},
		{"http://" + strings.Repeat("a", 4001), "wt_url_too_long"},
	}
	for _, tt := range failTests {
		t.Run(tt.value, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			if tt.exception != "" {
				require.Error(err)
				assert.Containsf(err.Error(), tt.exception, "missing %s from err: %s", tt.exception, err.Error())
				return
			}
			require.NoError(err)
		})
	}
}

func TestDomain_wt_email(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_email (
  id bigint generated always as identity primary key,
  email wt_email
);
`
		insert = `
insert into test_table_wt_email(email)
values ($1)
returning id;
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	failTests := []struct {
		value     string
		exception string
	}{
		{"   ", "wt_email_too_short"},
		{"1" + strings.Repeat("1", 320), "wt_email_too_long"},
		{"alice@bob.com", ""},
	}
	for _, tt := range failTests {
		t.Run(tt.value, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			if tt.exception != "" {
				require.Error(err)
				assert.Containsf(err.Error(), tt.exception, "missing %s from err: %s", tt.exception, err.Error())
				return
			}
			require.NoError(err)
		})
	}
}

func TestDomain_wt_full_name(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_full_name (
  id bigint generated always as identity primary key,
  full_name wt_full_name
);
`
		insert = `
insert into test_table_wt_full_name(full_name)
values ($1)
returning id;
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	failTests := []struct {
		value     string
		exception string
	}{
		{"   ", "wt_full_name_too_short"},
		{"1" + strings.Repeat("1", 512), "wt_full_name_too_long"},
		{"alice and bob's dinner", ""},
	}
	for _, tt := range failTests {
		t.Run(tt.value, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			if tt.exception != "" {
				require.Error(err)
				assert.Containsf(err.Error(), tt.exception, "missing %s from err: %s", tt.exception, err.Error())
				return
			}
			require.NoError(err)
		})
	}
}

func TestDomain_wt_name(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_name (
  id bigint generated always as identity primary key,
  name wt_name
);
`
		insert = `
insert into test_table_wt_name(name)
values ($1)
returning id;
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	failTests := []struct {
		value     string
		exception string
	}{
		{"   ", "wt_name_too_short"},
		{"1" + strings.Repeat("1", 512), "wt_name_too_long"},
		{"alice and bob's dinner", ""},
	}
	for _, tt := range failTests {
		t.Run(tt.value, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			if tt.exception != "" {
				require.Error(err)
				assert.Containsf(err.Error(), tt.exception, "missing %s from err: %s", tt.exception, err.Error())
				return
			}
			require.NoError(err)
		})
	}
}

func TestDomain_wt_description(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_description (
  id bigint generated always as identity primary key,
  description wt_description
);
`
		insert = `
insert into test_table_wt_description(description)
values ($1)
returning id;
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	failTests := []struct {
		value     string
		exception string
	}{
		{"   ", "wt_description_too_short"},
		{"1" + strings.Repeat("1", 1024), "wt_description_too_long"},
		{"alice and bob's dinner has delicious pancakes", ""},
	}
	for _, tt := range failTests {
		t.Run(tt.value, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			if tt.exception != "" {
				require.Error(err)
				assert.Containsf(err.Error(), tt.exception, "missing %s from err: %s", tt.exception, err.Error())
				return
			}
			require.NoError(err)
		})
	}
}

func TestDomain_wt_sentinel(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_sentinel (
  id bigint generated always as identity primary key,
  sentinel wt_sentinel
);
`
		insert = `
insert into test_table_wt_sentinel(sentinel)
values ($1)
returning id;
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"normal", "\ufffefoo\uffff", false},
		{"normal non-sentinel", "foo", false},
		{"empty-with-sentinel", "\ufffe\uffff", false},
		{"trailing sentinel", "\ufffefoo\ufffe", false},
		{"only start sentinel", "\ufffe", true},
		{"only end sentinel", "\uffff", true},
		{"sentinel with space before word", "\ufffe foo\uffff", false},
		{"sentinel with space after word", "\ufffefoo \uffff", false},
		{"start sentinel with empty string", "\ufffe  ", true},
		{"multiple sentinels with empty string", "\ufffe\ufffe  \uffff\uffff", false},
		{"multiple sentinels", "\ufffe\ufffefoo\uffff\uffff", false},
		{"multiple sentinels inverted", "\uffff\ufffffoo\ufffe\ufffe", false},
		{"sentinel space sentinel space string", "\ufffe \ufffe foo ", false},
		{"only spaces string", "  ", true},
		{"empty string", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			t.Logf("insert value: %q", tt.value)
			_, err := db.Query(insert, tt.value)
			if tt.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
		})
	}
}

func TestDomain_wt_is_sentinel(t *testing.T) {
	const (
		query = `
select wt_is_sentinel($1);
`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"normal", "\ufffefoo\uffff", true},
		{"non-sentinel", "foo", false},
		{"only start sentinel", "\ufffefoo", false},
		{"only end sentinel", "foo\uffff", false},
		{"trailing start sentinel", "\ufffefoo\ufffe", false},
		{"leading end sentinel", "\ufffffoo\uffff", false},
		{"sentinel with space before word", "\ufffe foo\uffff", true},
		{"sentinel with empty string", "\ufffe  \uffff", true},
		{"multiple start sentinels with empty string", "\ufffe\ufffe  \uffff", true},
		{"multiple start sentinels", "\ufffe\ufffefoo\uffff", true},
		{"only spaces", "  ", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			t.Logf("query value: %q", tt.value)

			var got bool
			rows, err := db.Query(query, tt.value)
			require.NoError(err)
			defer rows.Close()

			require.True(rows.Next())
			require.NoError(rows.Scan(&got))
			assert.Equal(tt.want, got)

			require.False(rows.Next())
			require.NoError(rows.Err())
		})
	}
}

func TestDomain_not_null_columns_func(t *testing.T) {
	const (
		createTable = `
create table if not exists test_not_null_columns (
  id bigint generated always as identity primary key,
  one text,
  two text,
  three text
);
`
		addTriggers = `
create trigger
  test_insert_not_null_columns
before
insert on test_not_null_columns
  for each row execute procedure not_null_columns('one', 'two');
`
		dropTriggers = `drop trigger test_insert_not_null_columns on test_not_null_columns`
	)
	ctx := context.Background()
	conn, _ := TestSetup(t, "postgres")
	db, err := conn.SqlDB(ctx)
	assert.NoError(t, err)

	_, err = db.Exec(createTable)
	assert.NoError(t, err)

	tests := []struct {
		name    string
		stmt    string
		wantErr bool
	}{
		{
			name:    "null one",
			stmt:    "insert into test_not_null_columns (one, two, three) values (null, 'two', 'three');",
			wantErr: true,
		},
		{
			name:    "null two",
			stmt:    "insert into test_not_null_columns (one, two, three) values ('one', null, 'three');",
			wantErr: true,
		},
		{
			name:    "all null",
			stmt:    "insert into test_not_null_columns (one, two, three) values (null, null, null);",
			wantErr: true,
		},
		{
			name:    "null three",
			stmt:    "insert into test_not_null_columns (one, two, three) values ('one', 'two', null);",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			_, err = db.Exec(addTriggers)
			require.NoError(err)

			_, err = db.Exec(tt.stmt)

			if !tt.wantErr {
				assert.NoError(err)
				return
			}
			require.Error(err)

			// Drop trigger and run insert again, it should now insert successfully
			_, err = db.Exec(dropTriggers)
			assert.NoError(err)

			_, err = db.Exec(tt.stmt)
			assert.NoError(err)
		})
	}
}
