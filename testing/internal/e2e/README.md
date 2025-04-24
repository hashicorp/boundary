# boundary-e2e-tests

This test suite tests Boundary in an end-to-end setting, utilizing both the Boundary CLI and the
Boundary Go API to exercise Boundary through various user workflows. It was designed to be run in a
variety of environments as long as the appropriate environment variables are set. The test suite
itself uses the standard [go test](https://pkg.go.dev/testing) library.

One method for setting up an environment is utilizing [Enos](https://github.com/hashicorp/Enos-Docs)
to create the desired infrastructure.

## Getting Started
### Enos
Setup Enos as described [here](../../../enos/README.md)

Then, use the following commands to run tests
```shell
cd enos
enos scenario list

# `Run` executes the tests and destroys the associated infrastructure in one command
enos scenario run e2e_{scenario} builder:local

# `Launch` executes the tests, but leaves the infrastructure online for debugging purposes
enos scenario launch e2e_{scenario} builder:local
enos scenario output  # displays any defined enos output
enos scenario destroy  # destroys infra
```

Enos scenarios set up the infrastructure, set the appropriate environment variables, and run the
specified tests in its scenario file.

Note: To run the `e2e_host_aws` scenario, you will need access to the boundary team's test AWS
account.

### Local
Set the appropriate environment variables...
```shell
export E2E_TESTS=true  # This is needed for any e2e test. Otherwise, the test is skipped

# For e2e/tests/base
export BOUNDARY_ADDR=  # e.g. http://127.0.0.1:9200
export E2E_PASSWORD_AUTH_METHOD_ID=  # e.g. ampw_1234567890
export E2E_PASSWORD_ADMIN_LOGIN_NAME=  # e.g. "admin"
export E2E_PASSWORD_ADMIN_PASSWORD=  # e.g. "password"

export E2E_TARGET_ADDRESS=  # e.g. 192.168.0.1
export E2E_TARGET_PORT=  # e.g. 22
export E2E_SSH_KEY_PATH=  # e.g. /Users/username/key.pem
export E2E_SSH_USER=  # e.g. ubuntu

# For e2e/tests/base_with_vault
export BOUNDARY_ADDR=  # e.g. http://127.0.0.1:9200
export E2E_PASSWORD_AUTH_METHOD_ID=  # e.g. ampw_1234567890
export E2E_PASSWORD_ADMIN_LOGIN_NAME=  # e.g. "admin"
export E2E_PASSWORD_ADMIN_PASSWORD=  # e.g. "password"

export VAULT_ADDR=  # e.g. http://127.0.0.1:8200
export VAULT_TOKEN=
export E2E_TARGET_ADDRESS=  # e.g. 192.168.0.1
export E2E_TARGET_PORT=  # e.g. 22
export E2E_SSH_KEY_PATH=  # e.g. /Users/username/key.pem
export E2E_SSH_USER=  # e.g. ubuntu

# For e2e/tests/aws
export BOUNDARY_ADDR=  # e.g. http://127.0.0.1:9200
export E2E_PASSWORD_AUTH_METHOD_ID=  # e.g. ampw_1234567890
export E2E_PASSWORD_ADMIN_LOGIN_NAME=  # e.g. "admin"
export E2E_PASSWORD_ADMIN_PASSWORD=  # e.g. "password"

export E2E_AWS_ACCESS_KEY_ID=
export E2E_AWS_SECRET_ACCESS_KEY=
export E2E_AWS_HOST_SET_FILTER=  # e.g. "tag:testtag=true"
export E2E_AWS_HOST_SET_IPS=  # e.g. "[\"1.2.3.4\", \"2.3.4.5\"]"
export E2E_AWS_HOST_SET_FILTER2=  # e.g. "tag:testtagtwo=test"
export E2E_AWS_HOST_SET_IPS2=  # e.g. "[\"1.2.3.4\"]
export E2E_SSH_KEY_PATH=  # e.g. /Users/username/key.pem
export E2E_SSH_USER=  # e.g. ubuntu

# For e2e/tests/database
export E2E_AWS_ACCESS_KEY_ID=
export E2E_AWS_SECRET_ACCESS_KEY=
export E2E_AWS_HOST_SET_FILTER=  # e.g. "tag:testtag=true"
export VAULT_ADDR=  # e.g. http://127.0.0.1:8200
export VAULT_TOKEN=
```

Then, run...
```shell
go test github.com/hashicorp/boundary/testing/internal/e2e/tests/base
go test ./target/ // run target tests if running from this directory
go test github.com/hashicorp/boundary/testing/internal/e2e/tests/base -v // verbose
go test github.com/hashicorp/boundary/testing/internal/e2e/tests/base -v -run '^TestCreateTargetApi$' // run a specific test
```

## Adding Tests

Tests live in the `tests/` directory. Additional tests can be added to an existing go package or a
new one can be created. If a new package is created, a new enos scenario would also need to be
created.

Enos is comprised of scenarios, where a scenario is the environment you want the tests to operate
in. In one scenario, there may be a boundary cluster and a target. Another scenario might involve a
boundary cluster and a vault instance. Scenarios can be found in [boundary/enos](../../../enos/)

To run these tests in CI, the [enos-run.yml](../../../.github/workflows/enos-run.yml) github action
workflow must be updated to include the new scenario (see the `matrix`).

### Development
To assist with iterating on tests on enos launched infrastructure, you can perform the following...

Launch an enos scenario and print out the environment variables
```
cd enos
enos scenario launch e2e_{scenario} builder:local
bash scripts/test_e2e_env.sh
```

Take the printed environment variable information and export them into another terminal session
```
export BOUNDARY_ADDR=
export E2E_PASSWORD_AUTH_METHOD_ID=
...
```
Run your tests
```
go test -v {go package}
```
