# Contributing to Boundary

Thank you for contributing to Boundary! Here you can find common questions around reporting issues and opening
pull requests to our project.

When contributing in any way to the Boundary project (new issue, PR, etc), please be aware that our team identifies with many gender pronouns. Please remember to use nonbinary pronouns (they/them) and gender neutral language ("Hello folks") when addressing our team. For more reading on our code of conduct, please see the [HashiCorp community guidelines](https://www.hashicorp.com/community-guidelines). 

## Issue Reporting
### Reporting Security Related Vulnerabilities

We take Boundary's security and our users' trust very seriously. If you believe you have found a security issue 
in Boundary, please responsibly disclose by contacting us at security@hashicorp.com. Do not open an issue on 
our GitHub issue tracker if you believe you've found a security related issue, thank you!

### Bug Fixes

If you believe you found a bug with Boundary, please:

1. Build from the latest `main` HEAD commit to attempt to reproduce the issue. It's possible we've already fixed
the bug, and this is a first good step to ensuring that's not the case.
1. Take a look at the [Boundary Discuss](https://discuss.hashicorp.com/c/boundary/50) to see if other folks have had
similar issues.
1. Ensure a similar ticket is not already opened by searching our opened issues on GitHub.


Once you've verified the above, feel free to open a bug fix issue template type from our [issue selector](https://github.com/hashicorp/boundary/issues/new/choose)
and we'll do our best to triage it as quickly as possible. 

## Pull Requests

### New Features & Improvements

Before writing a line of code, please ask us about a potential improvement or feature that you want to write into Boundary. We may already be working on it; even if we aren't, we need to ensure that both the feature and its proposed implementation is aligned with our road map, vision, and standards for the project. We're happy to help walk through that via a [feature request issue](https://github.com/hashicorp/boundary/issues/new/choose).

You can see a public [road map for Boundary](https://github.com/hashicorp/boundary/issues/new/choose) on our docs site and we encourage
everyone to look this over to understand at a high level what we're working on with Boundary.

### Submitting a New Pull Request

When submitting a pull request, please ensure:

1. You've added a changelog line clearly describing the new addition under the correct changelog sub-section.
1. You've followed the above guidelines for contributing to Boundary.

Once you open your PR, our auto-labeling will add labels to help us triage and prioritize your contribution. Please
allow us a couple of days to comment, request changes, or approve your PR. Thank you for your contribution!

## Changelog

The changelog is updated by PR contributors. Each contribution to Boundary should include a changelog update at the contributor or reviewer discretion. 
The changelog should be updated when the contribution is large enough to warrant it being called out in the larger release cycle. Enhancements, bug fixes,
and other contributions that practitioners might want to be aware of should exist in the changelog. 

When contributing to the changelog, follow existing patterns for referencing PR's, issues or other ancillary context.

The changelog is broken down into sections:

### vNext

The current release cycle. New contributions slated for the next release should go under this heading. If the contribution is being backported,
the inclusion of the feature in the appropriate release during the backport process is handled on an as-needed basis. 

### New and Improved

Any enhancements, new features, etc fall into this section. 

### Bug Fixes

Any bug fixes fall into this section.

## Testing

Most tests require a postgres database instance to successfully run.
This is provided via docker
by running a customized postgres image that is optimized for boundary tests.

Before running the test suite, this docker container must be started:

```
$ make test-database-up
```

This can take a few seconds to initialize as it will
create a template database with the boundary migrations.
The progress can be checked b running:

```
$ docker logs -f boundary-sql-tests
```

Once a log line like the following is seen, the container is ready for running
tests:

```
PostgreSQL init process complete; ready for start up.
```

Alternatively if the `pg_isready` command is installed, it can be used to
determine if the container is ready, i.e.:

```
$ until pg_isready -h 127.0.0.1; do sleep 1; done
```

To run the entire test suite run this command in the root of the project
once the test database is ready:

```
$ make test
```

Before running any test please ensure that Docker is started. Boundary uses a Docker container to initiate a database for testing.
If a test is interrupted check to make certain that all Docker containers have been properly destroyed. 

### Running individual tests

If you don't want to run the entire test suite, you can just run a single test
with go. For example, if you wanted to run the tests TestAuthTokenAuthenticator, you would
run:

```
$ go test -run TestAuthTokenAuthenticator -v ./internal/auth
```

### Stopping the test database container

The test database container can be shutdown using:

```
$ make test-database-down
```

Note that the container does *not* need to be shutdown between each run of
`make test` or `go test`.

### Test database container options

By default the container uses the host port of 5432.
This can changed using an environment variable:

```
$ export TEST_DB_PORT=5433
$ make test-database-up
$ make test
```

By default the container name is `boundary-sql-tests`.
This can be changed in the same way as the port:

```
$ export TEST_CONTAINER_NAME="custom-name"
$ make test-database-up
$ docker logs custom-name
```

The default docker image is built using the `postgres:12` base image.
The image can be changed using a make option to test against other versions:

```
$ make IMAGE_TAG=docker.io/hashicorpboundary/postgres:12-alpine test-database-up
$ make IMAGE_TAG=docker.io/hashicorpboundary/postgres:13-alpine test-database-up
$ make IMAGE_TAG=docker.io/hashicorpboundary/postgres:alpine test-database-up
```

Additional options can be passed to postgres to customize and override the
configuration in the config file of the docker image.
See the troubleshooting section below for more details.

### Troubleshooting test database container

The postgres configuration file included in the image
is optimized to support running the full test suite in parallel in CI.
As such, there may be issues starting the container locally,
especially in cases where the container has less then 4GB of memory.

This is likely the case if the output of `docker logs boundary-sql-tests` shows:

```
pg_ctl: could not start server
```

In this case adjust the
[max_connections](https://www.postgresql.org/docs/11/runtime-config-connection.html#GUC-MAX-CONNECTIONS)
and/or
[shared_buffers](https://www.postgresql.org/docs/11/runtime-config-resource.html#GUC-SHARED-BUFFERS):

```
make PG_OPTS="-c max_connections=1000" test-database-up
```

Note that if `max_connections` is set too low, it may result in sporadic test
failures if a connection cannot be established. In this case, reduce the number
of concurrent tests via `GOMAXPROCS` or selectively run tests.

### SDK and API tests

Tests for the SDK and API modules can also be run. These do not require a test
database:

```
$ make test-api
$ make test-sdk
```

Or all of the test can be run with a single target:

```
$ make test-all
```

## Performance
### Database Indexes

Most of the indexes in the database are for enforcing data constraints.
We have not added indexes for improving performance because we do not have a way
to measure and test these types of indexes.
We want a way to test and verify that indexes added to improve performance are actually being used by the system.
And we want these same tests to fail when an index stops being used as we evolve the system.
This is on our roadmap but we have not started work on it yet.

## Additional docs

* [Adding fields to the API](internal/adding-a-new-field-readme.md)
