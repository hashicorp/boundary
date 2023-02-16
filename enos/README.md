# Enos

Enos is an quality testing framework that allows composing and executing quality
requirement scenarios as code. For Boundary, it is currently used to perform
infrastructure integration testing using the artifacts that are created as part
of the CRT build pipeline. While intended to be executed via Github Actions using
the results of the `build` workflow, scenarios are executable from a developer
machine that has the requisite dependencies and configuration.

Refer to the [enos documentation](https://github.com/hashicorp/Enos-Docs)
for further information regarding installation, execution or composing Enos scenarios.

## Requirements
* AWS access. HashiCorp Boundary developers should use Doormat.
* Terraform >= 1.0
* Enos >= v0.0.10. You can [install it from a release channel](https://github.com/hashicorp/Enos-Docs/blob/main/installation.md) or use `make tools` install it into `$GOBIN`.
* Access to the QTI org in Terraform Cloud. HashiCorp Boundary developers can
  access this token in 1Password or request their own in #team-quality on slack.
* An SSH keypair in the AWS region you wish to run the scenario. You can use
  doormat to login to the AWS console to create or upload an existing keypair.
* Boundary installed locally. `make install` will put it in `$GOPATH/bin`, which
  you can use with the `local_boundary_dir` variable, e.g.
  `local_boundary_dir = /Users/<user>/.go/bin`.
* For the Bats CLI UI scenarios, you'll need `bats`, `jq` and a valid keychain
  configured. Windows and macOS will use the system keychains by default. If
  you're using Linux it will default to [pass](https://www.passwordstore.org/).

## Scenarios Variables
In CI, each scenario is executed via Github Actions and has been configured using
environment variable inputs that follow the `ENOS_VAR_varname` pattern.

For local execution you can specify all the required variables using environment
variables, or you can update `enos.vars.hcl` with values and uncomment the lines.

Variables that are required:
- `tfc_api_token`
- `aws_ssh_private_key_path`
- `aws_ssh_keypair_name`
- `enos_user`
- `local_boundary_dir`

If you want to use the `builder:crt` variant to simulate execution in CI you'll
also need to specify `crt_bundle_path` to a local boundary install bundle.

If you want to modify which port the ALB listens on to proxy controller API
requests, you can specify the `alb_listener_api_port`.

See [enos.vars.hcl](./enos.vars.hcl) for complete descriptions of each variable.

## Executing Scenarios
From the `enos` directory:

```bash
# list all available scenarios
enos scenario list
# run the cli_ui scenario with an artifact that is built locally. Make sure
# the local machine has been configured for the cli_ui scenario as detailed in
# the requirements section. This will execute the scenario and clean up any
# resources if successful.
enos scenario run integration builder:local test:cli_ui
# launch an individual scenario but leave infrastructure up after execution
enos scenario launch integration builder:local test:cli_ui
# check an individual scenario for validity. This is useful during scenario
# authoring and debugging.
enos scenario validate integration builder:local test:cli_ui
# if you've run the tests and need to outputs, such as the URL or credentials,
# you can run the output command to see them. Please note that after "run" or
# destroy there will be no "outputs" as the infrastructure will have been
# destroyed.
enos scenario output integration builder:local test:cli_ui
# explicitly destroy all existing infrastructure
enos scenario destroy integration builder:local test:cli_ui
```

Refer to the [enos documentation](https://github.com/hashicorp/Enos-Docs)
for further information regarding installation, execution or composing scenarios.

# Scenarios

## Infrastructure Integration
The `integration` scenario has multiple variants which enable it to run different
test suites against Boundary clusters. You can control which `boundary` artifacts
are installed for the controllers and workers by specifing the `builder` variant.
It support either a local build or the output of the `build` workflow (CRT). All
test scenarios create a Boundary cluster consisting of an RDS database, 1 worker, and
1 controller (behind an ALB). The count and instance type for  workers and
controllers is configurable. All tests require that a local copy of `boundary`
is availble in the `local_boundary_dir` to access the Boundary cluster API
through the ALB. For example, if you install `boundary` locally via `make install`
you could test that version against the cluster by setting `local_boundary_dir` to
`/Users/<user>/.go/bin`, or wherever you have configured `$GOPATH/bin`.

### Variants
  * `builder:crt`
    Scenarios that include the `builder:crt` variant require that the
    `crt_bundle_path` variable is set to the directory of an install bundle of
    Boundary, such as one might find in Artifactory, `releases.hashicorp.com`,
    or the output of the `build` workflow (CRT).
  * `builder:local`
    The `builder:local` variant will build an install bundle as part of the
    scenario and copy it to each worker and controller node. This allows you
    to execute the scenario using an artifact of the current branch.
  * `test:smoke`
    The `test:smoke` variant runs a basic smoke test. It first provisions one
    or more "target" nodes that don't have access on port 22. It then creates a
    test catalog and host set and adds each of the "target" node(s) as
    hosts/targets. It then SSH's to the target using `boundary` to verify that
    it is able.
  * `test:cli_ui`
    The `test:cli_ui` variant creates implied dependencies for the Bats CLI UI tests
    in the Boundary cluster and then executes the Bats CLI UI tests against it. This
    scenario requires the machine executing `enos` to be configured for the Bats
    tests as described in the Requirements section.

## End-to-end tests

Scenarios with `e2e_` invoke an end-to-end test suite written in Go. Different tests
are invoked depending on the scenario.

# CI Bootstrap
In order to execute any of the scenarios in this repository, it is first necessary to bootstrap the
CI AWS account with the required permissions, service quotas and supporting AWS resources. There are
two Terraform modules which are used for this purpose, [service-user-iam](./ci/service-user-iam) for
the account permissions, and service quotas and [bootstrap](./ci/bootstrap) for the supporting resources.

## Bootstrap Process
These steps should be followed to bootstrap this repo for enos scenario execution:

### Set up CI service user IAM role and Service Quotas
The service user that is used when executing enos scenarios from any GitHub Action workflow must have
a properly configured IAM role granting the access required to create resources in AWS. Additionally,
service quotas need to be adjusted to ensure that normal use of the ci account does not cause any
service quotas to be exceeded. The [service-user-iam](./ci/service-user-iam) module contains the IAM
Policy and Role for that grants this access as well as the service quota increase requests to adjust
the service quotas. This module should be updated whenever a new AWS resource type is required for a
scenario or a service quota limit needs to be increased. Since this is persistent and cannot be created
and destroyed each time a scenario is run, the Terraform state will be managed by Terraform Cloud.
Here are the steps to configure the GitHub Actions service user:

#### Pre-requisites
- Access to the `hashicorp-qti` organization in Terraform Cloud.
- Full access to the CI AWS account is required.

**Notes:**
- For help with access to Terraform Cloud and the CI Account, contact the QT team on Slack (#team-quality)
  for an invite. After receiving an invite to Terraform Cloud, a personal access token can be created
  by clicking `User Settings` --> `Tokens` --> `Create an API token`.
- Access to the AWS account can be done via Doormat, at: https://doormat.hashicorp.services/.
    - The account name uses the following pattern: `<repository>-ci`, e.g. `boundary-ci` for the boundary repo.
    - Access can be requested by clicking: `Cloud Access` --> `AWS` --> `Request Account Access`.

1. **Create the Terraform Cloud Workspace** - The name of the workspace to be created depends on the
   repository for which it is being created, but the pattern is: `<repository>-ci-service-user-iam`,
   e.g. `boundary-ci-service-user-iam`. It is important that the execution mode for the workspace be 
   set to `local`. For help on setting up the workspace, contact the QT team on Slack (#team-quality)


2. **Execute the Terraform module**
```shell
> cd ./enos/ci/service-user-iam
> export TF_WORKSPACE=<repo name>-ci-enos-service-user-iam
> export TF_TOKEN_app_terraform_io=<Terraform Cloud Token>
> export TF_VAR_repository=<repository name>
> terraform init
> terraform plan
> terraform apply -auto-approve
```

### Bootstrap the CI resources
Bootstrapping of the resources in the CI account is accomplished via the GitHub Actions workflow:
[enos-bootstrap-ci](../.github/workflows/enos-bootstrap-ci.yml). Before this workflow can be run a
workspace must be created as follows:

1. **Create the Terraform Cloud Workspace** - The name workspace to be created depends on the repository
   for which it is being created, but the pattern is: `<repository>-ci-bootstrap`, e.g.
   `boundary-ci-bootstrap`. It is important that the execution mode for the workspace be set to
   `local`. For help on setting up the workspace, contact the QT team on Slack (#team-quality).

Once the workspace has been created, changes to the bootstrap module will automatically be applied via
the GitHub PR workflow. Each time a PR is created for changes to files within that module the module
will be planned via the workflow described above. If the plan is ok and the PR is merged, the module
will automatically be applied via the same workflow.
