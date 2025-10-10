# Enos

Enos is an quality testing framework that allows composing and executing quality
requirement scenarios as code. For Boundary, it is currently used to perform
infrastructure integration testing using the artifacts that are created as part
of the CRT build pipeline. While intended to be executed via Github Actions using
the results of the `build` workflow, scenarios are executable from a developer
machine that has the requisite dependencies and configuration.

Refer to the [enos documentation](https://github.com/hashicorp/Enos-Docs)
for further information regarding installation, execution, or composing Enos scenarios.

## Setup
* Terraform >= 1.0
* Vault >= 1.12.2
* Enos >= v0.0.28
* Doormat
```shell
brew tap hashicorp/tap
brew install hashicorp/tap/vault
brew install hashicorp/tap/terraform
brew install hashicorp/tap/enos
brew install coreutils

# Install doormat cli
brew tap hashicorp/security git@github.com:hashicorp/homebrew-security.git
brew install hashicorp/security/doormat-cli
```

* AWS access. HashiCorp Boundary developers should use Doormat.
* An SSH keypair in the AWS region you wish to run the scenario. You can use
  doormat to login to the AWS console to create or upload an existing keypair.
```shell
# Create a SSH Key Pair
ssh-keygen -t ed25519 -C "your_email@example.com"

# <https://doormat.hashicorp.services/>
# Go to the console for the corresponding AWS account
# Select the desired AWS region on the top-right
# Go to EC2 -> Key Pairs -> Actions -> Import Key Pair -> Import public key file (.pub)
# Note the name of the key pair
```
* Boundary CLI installed locally

### Enos Variables
In CI, each scenario is executed via Github Actions and has been configured using
environment variable inputs that follow the `ENOS_VAR_varname` pattern.

For local execution you can specify all the required variables using environment
variables, or you can update `enos.vars.hcl` with values and uncomment the lines.

If you want to use the `builder:crt` variant to simulate execution in CI you'll
also need to specify `crt_bundle_path` to a local boundary install bundle.

See [enos.vars.hcl](./enos.vars.hcl) for complete descriptions of each variable.

You can either modify `enos.vars.hcl` directly or create your own copy at
`enos-local.vars.hcl` which gets ignored by git.

### System File Modifications

For docker-based scenarios, you will need to modify `/etc/hosts` to include the
following lines
```
127.0.0.1       localhost       boundary
127.0.0.1       localhost       worker
127.0.0.1       localhost       vault
```
### AWS Credentials
Copy the AWS Account credentials from doormat and set it in the terminal, where the enos commands are run.

## Executing Scenarios
From the `enos` directory:

```bash
# List all available scenarios. Scenarios can be found in enos/enos-scenario*
enos scenario list

# Launch an individual scenario but leave infrastructure up after execution
enos scenario launch e2e_aws builder:local

# Explicitly destroy all existing infrastructure
enos scenario destroy integration builder:local
```

Refer to the [enos documentation](https://github.com/hashicorp/Enos-Docs)
for further information regarding installation, execution or composing scenarios.

To get information about the environment that was created...
```shell
# Scenarios that start with `e2e` can get environment information using a script. It can be helpful to set some aliases in your shell profile
alias enosenv="source <(. ${BOUNDARY_REPO}/enos/scripts/test_e2e_env.sh); . ${BOUNDARY_REPO}/enos/scripts/test_e2e_env.sh"
alias enosenvent="source <(. ${BOUNDARY_ENTEPRISE_REPO}/enos/scripts/test_e2e_env.sh); . ${BOUNDARY_ENTEPRISE_REPO}/enos/scripts/test_e2e_env.sh"

# Some scenarios don't start with `e2e` can get environment information using an enos command
enos scenario output hcp_session_recording builder:local
```

# Scenarios

## Infrastructure Integration
The `integration` scenario has multiple variants which enable it to run different
test suites against Boundary clusters. You can control which `boundary` artifacts
are installed for the controllers and workers by specifing the `builder` variant.
It support either a local build or the output of the `build` workflow (CRT). All
test scenarios create a Boundary cluster consisting of an RDS database, 1 worker, and
1 controller (behind an ALB). The count and instance type for  workers and
controllers is configurable. All tests require that a local copy of `boundary`
is available in the `local_boundary_dir` to access the Boundary cluster API
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
