package db

import (
	"testing"

	_ "github.com/jackc/pgx/v4"
)

func TestDomain_PublicId(t *testing.T) {
	const (
		createTable = `
create table test_table (
  id bigint generated always as identity primary key,
  public_id wt_public_id
);
`
		insert = `
insert into test_table (public_id)
values ($1)
returning id;
`
	)

	cleanup, conn, _ := TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()

	db := conn.DB()
	defer db.Close()

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
create table test_table (
  id bigint generated always as identity primary key,
  name text,
  good_time wt_timestamp,
  bad_time timestamp default current_timestamp
);
`
		insert = `
insert into test_table (name)
values ($1)
returning id;
`
	)

	cleanup, conn, _ := TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()

	db := conn.DB()
	defer db.Close()
	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	if _, err := db.Exec(insert, "foo"); err != nil {
		t.Fatalf("want no error, got error %v", err)
	}

	if _, err := db.Query("select extract(timezone from good_time) from test_table;"); err != nil {
		t.Errorf("want no error, got error %v", err)
	}

	if _, err := db.Query("select extract(timezone from bad_time) from test_table;"); err == nil {
		t.Errorf("want error, got no error")
	}
}
