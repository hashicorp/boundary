// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbassert

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	_ "github.com/lib/pq"
)

var (
	StartDbInDocker = startDbInDockerUnsupported

	ErrDockerUnsupported = errors.New("docker is not currently supported on this platform")
)

// MockTesting provides a testing.T mock.
type MockTesting struct {
	err bool
	msg string
}

// HasError returns if the MockTesting has an error for a previous test.
func (m *MockTesting) HasError() bool {
	return m.err
}

// ErrorMsg returns if the MockTesting has an error msg for a previous
// test.
func (m *MockTesting) ErrorMsg() string {
	return m.msg
}

// Errorf provides a mock Errorf function.
func (m *MockTesting) Errorf(format string, args ...interface{}) {
	m.msg = fmt.Sprintf(format, args...)
	m.err = true
}

// FailNow provides a mock FailNow function.
func (m *MockTesting) FailNow() {
	m.err = true
}

// Reset will reset the MockTesting for the next test.
func (m *MockTesting) Reset() {
	m.err = false
	m.msg = ""
}

// AssertNoError asserts that the MockTesting has no current error.
func (m *MockTesting) AssertNoError(t *testing.T) {
	t.Helper()
	if m.HasError() {
		t.Error("Check should not fail")
	}
}

// AssertError asserts that the MockTesting has a current error.
func (m *MockTesting) AssertError(t *testing.T) {
	t.Helper()
	if !m.HasError() {
		t.Error("Check should fail")
	}
}

// TestSetup sets up the testing env, including starting a docker container
// running the db dialect and initializing the test database schema.
func TestSetup(t *testing.T, dialect string) (func() error, *sql.DB, string) {
	cleanup, url, _, err := StartDbInDocker(dialect)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open(dialect, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := initStore(t, db); err != nil {
		t.Fatal(err)
	}
	return cleanup, db, url
}

func initStore(t *testing.T, db *sql.DB) error {
	const (
		createDomainType = `
create domain dbasserts_public_id as text
check(
  length(trim(value)) > 10
);
comment on domain dbasserts_public_id is
'dbasserts test domain type';
`
		createTable = `
create table if not exists test_table_dbasserts (
  id bigint generated always as identity primary key,
  public_id dbasserts_public_id not null,
  nullable text,
  type_int int
);
comment on table test_table_dbasserts is
'dbasserts test table'
`
	)
	if _, err := db.Exec(createDomainType); err != nil {
		return err
	}
	if _, err := db.Exec(createTable); err != nil {
		return err
	}
	return nil
}

func startDbInDockerUnsupported(string) (func() error, string, string, error) {
	return nil, "", "", ErrDockerUnsupported
}
