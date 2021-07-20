# SQL Tests

This test suite is used to test behavior of the database logic.
In particular the data warehouse implementation is
completely in sql via plpgsql, functions, and triggers.
This test suite is also implemented directly in sql.

## Organization

- `initdb.d`: contains init scripts/sql that is run on the test database
 when it starts. It ensures the sql migrations are run and creates test helper
 functions.
- `tests`: contains the tests. Each file can contain only a single test that
    runs in a transaction so it can rollback.

The tests leverage the
[pgTap](https://pgtap.org/documentation.html)
postgres extension to make assertions and provide
more readable test output.

## Usage

To run the test run `make` or `make test`. This will:

- Start a docker `postgres` container and initialize it.
- Start a docker `pgtap` container to execute the tests.
