# boundary-e2e-tests

This test suite tests Boundary in an end-to-end setting using [Enos](https://github.com/hashicorp/Enos-Docs) to spin up the desired infrastructure and [go test](https://pkg.go.dev/testing) to perform user workflows.

## Getting Started
### Usage
#### Enos
Setup Enos as described [here](../../enos/README.md)

```shell
enos scenario run e2e_{scenario} builder:local // runs and destroys infra

enos scenario launch e2e_{scenario} builder:local  // runs and keeps infra online
enos scenario output // displays any defined enos output

enos scenario destroy // destroys infra
```

Enos scenarios set up the infrastructure, set the appropriate environment variables, and run the selected tests. Folders in this directory correspond to an enos scenario (e.g. `enos/enos-scenario-e2e-target.hcl` runs tests in `testing/e2e/target`)

#### Local
Set the appropriate environment variables...
```shell
export BOUNDARY_ADDR=  # e.g. http://127.0.0.1:9200
export E2E_PASSWORD_AUTH_METHOD_ID=  # e.g. ampw_1234567890
export E2E_PASSWORD_ADMIN_LOGIN_NAME=  # e.g. "admin"
export E2E_PASSWORD_ADMIN_PASSWORD=  # e.g. "password"

# For e2e/target
export E2E_TARGET_IP=  # e.g. 192.168.0.1
export E2E_SSH_KEY_PATH=  # e.g. /Users/username/key.pem
export E2E_SSH_USER=  # e.g. ubuntu

# For e2e/credential/vault
export VAULT_ADDR=  # e.g. http://127.0.0.1:8200
export VAULT_TOKEN=
export E2E_TARGET_IP=  # e.g. 192.168.0.1
export E2E_SSH_KEY_PATH=  # e.g. /Users/username/key.pem
export E2E_SSH_USER=  # e.g. ubuntu
```

Then, run...
```shell
go test github.com/hashicorp/boundary/testing/e2e/target // run target tests
go test ./target/ // run target tests if running from this directory
go test github.com/hashicorp/boundary/testing/e2e/target -v // verbose
go test github.com/hashicorp/boundary/testing/e2e/target -v -run '^TestCreateTargetApi$' // run a specific test
```
