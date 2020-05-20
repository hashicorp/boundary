package db

import (
	"testing"

	_ "github.com/jackc/pgx/v4"
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
	defer conn.Close()

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
	defer conn.Close()

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
	const (
		createTable = `
create table if not exists test_immutable_create_time (
  id bigint generated always as identity primary key,
  name text,
  create_time wt_timestamp
);
`
		addTriggers = `
CREATE TRIGGER test_update_immutable_create_time
BEFORE
update ON test_immutable_create_time FOR EACH ROW EXECUTE PROCEDURE immutable_create_time_func();
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
	)

	cleanup, conn, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer conn.Close()

	db := conn.DB()
	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}
	if _, err := db.Exec(addTriggers); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	if _, err := db.Exec(insert); err != nil {
		t.Fatalf("wanted no error, got %s", err)
	}

	var count int
	err := db.QueryRow("select count(*) from test_immutable_create_time;").Scan(&count)
	if err != nil {
		t.Errorf("want no error, got error %v", err)
	}
	if count != 1 {
		t.Errorf("want one row, got %d", count)
	}
	if _, err := db.Exec(update); err != nil {
		t.Fatalf("want no, got %v", err)
	}

	if _, err := db.Exec(bad_update); err == nil {
		t.Fatal("wanted an error")
	}

}
