# Resources for HCP testing

This Terraform module defines resources needed to test against a long-lived HCP cluster.

## Prerequisites

- Gain access to the TFC `hashicorp-qti` org
- Generate a TFC API token under *Account Settings* > *Tokens*

## Usage

```shell
# Get AWS account credentials
doormat login
source <(doormat aws export --account ${AWS_ACCOUNT})

terraform login # enter TFC API token to the hashicorp-qti org
terraform init
terraform plan
terraform apply
```

The output contains information that we will need. For sensitive values, we will
need to use these commands.

```shell
terraform state pull | jq .outputs.worker_tokens.value
terraform state pull | jq .outputs.bucket_secret_access_key.value
```

You can also find output information using the TFC UI by navigating to the
`boundary-hcp-resources` workspace.

If any of these values have changed, we will need to update the Vault instance
that stores these values.

## Notes

- Created a `boundary-hcp-resources` workspace in the TFC org
  - Set *Workflow* to `CLI-Driven`
  - Set *Execution Mode* to `Local`
