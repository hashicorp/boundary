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

When writing new tests
it can be faster to keep the database up
and just re-run the tests.
This can be done by running:

```bash
# starts database docker image in the background
make database-up

# runs the tests, call this multiple times while implementing new tests.
make run-tests

# to clean up
make clean
```

You can also run individual tests:

```bash
# run a single test file
make TEST=tests/setup/wtt_load.sql

# run a single test file with the database already created.
make run-tests TEST=tests/setup/wtt_load.sql

# run a directory of tests
make TEST=tests/setup/*.sql
```

You can pass through options to `pg_prove`.
See [the docs](https://pgtap.org/pg_prove.html)
for available options, i.e:

```bash
# run tests in parallel with verbose output
make PROVE_OPTS='-j9 -v'
```

Different versions of postgres can easily be tested:

```bash
make PG_DOCKER_TAG=latest
make PG_DOCKER_TAG=13-alpine
make PG_DOCKER_TAG=12-alpine
make PG_DOCKER_TAG=11-alpine
```
