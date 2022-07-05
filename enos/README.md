# Enos scenarios for Boundary
Here you'll find Enos scenarios for Boundary. These scenarios are intended to
deploy Boundary in a real world scenarios and assert that the software behaves
as expected.

## Requirements
These scenarios are intended to represent a common deployment of Boundary. As
such, they create an entire cluster in AWS. The scenarios have the following
common requirements:

* AWS access (HashiCorp Boundary developers should use doormat)
* Terraform >= 1.0
* Enos >= v0.0.9
* Access to the QTI org in Terraform Cloud. HashiCorp Boundary developers can
  access this token in 1Password or request their own in #team-quality.
* An SSH keypair in the AWS region you wish to run the scenario.
* Boundary installed locally. The `make` targets that configure and run scenarios
  will assume you've got Boundary installed in your $GOPATH. Depending on the
  target build mode variant, it will either build a Boundary for the target
  machines or use the same binaries that are built by CRT/build.yml.

## Scenarios Variables
Each scenario has provided an `enos.vars.hcl` file with example values. You can
either modify them or override them using environment variables that match the
`ENOS_VAR_varname` pattern.

## Executing Scenarios
From the `enos` directory:

```bash
# runs all scenarios and cleans up all test resources
make
# or run an individual scenario, leaving instances up for running
make fresh-install-launch
# check an individual scenario
make fresh-install-validate
# if you've run the tests and need to see default URL/credentials again
make fresh-install-output
# explicitly destroy
make fresh-install-destroy
```

# Scenarios

## Fresh Install
The fresh_install scenario creates a boundary cluster consisting of (by default)
an RDS database, 1 worker, 1 controller (behind an ALB), and 1 "target" nodes. It
runs a basic smoke test that gets a Boundary Auth token, creates a test catalog
and host set, adds the "target" node(s) as hosts/targets and attempts to SSH to
a target to verify that it is able.

Many of the default parameters can be changed to increase the size of the cluster.

It has two variants. You can either have it build a new version of Boundary from
the current branch that is checked out, or you opt for using a pre-built release
bundle. The latter option is used to test bundled artifacts that are created
by CRT.
