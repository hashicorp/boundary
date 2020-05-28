package db

import (
	"testing"
	"time"

	"github.com/golang-sql/civil"
	_ "github.com/jackc/pgx/v4"
	"github.com/stretchr/testify/assert"
)

func TestDomain_PublicId(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_public_id (
  id bigint generated always as identity primary key,
  public_id wt_public_id
);
`
		insert = `
insert into test_table_public_id (public_id)
values ($1)
returning id;
`
	)

	cleanup, conn, _ := TestSetup(t, "postgres")
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
	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	failTests := []string{
		" ",
		"bar",
		"00000009",
	}
	for _, tt := range failTests {
		value := tt
		t.Run(tt, func(t *testing.T) {
			t.Logf("insert value: %q", value)
			if _, err := db.Query(insert, value); err == nil {
				t.Errorf("want error, got no error for inserting public_id: %s", value)
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

	cleanup, conn, _ := TestSetup(t, "postgres")
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

	cleanup, conn, _ := TestSetup(t, "postgres")
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()

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

	cleanup, conn, _ := TestSetup(t, "postgres")
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()

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
