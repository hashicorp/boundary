# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

// Example variable inputs. Set these to valid values and uncomment them before
// running scenarios.

// Recommended to copy this file to enos-local.vars.hcl and modify the values
// there to avoid accidentally committing sensitive information.

// ==============================================================================
// REQUIRED VARIABLES
// ==============================================================================
// Build edition
// If using community edition, set to "oss"
// If using enterprise edition, set to "enterprise"
// boundary_edition = "oss"

// Prevents the end-to-end test suites from running when starting scenarios.
// Recommend setting this to true unless running in CI.
// e2e_debug_no_run = true

// The AWS region you want to create the resources in. Make sure you choose a
// region where you've got an AWS keypair. Applies to AWS scenarios only.
// aws_region = "us-east-1"

// The name of the AWS keypair in EC2 -> Key Pairs. Ensure this key pair is
// available in the selected region. Applies to AWS scenarios only.
// aws_ssh_keypair_name = "mykeypair"

// The path to the local copy of the private key associated with your keypair.
// Applies to AWS scenarios only.
// aws_ssh_private_key_path = "/Users/<user>/.ssh/mykeypair.pem

// Name of user. This is used to tag resources in AWS to more easily identify
// your resources. Can be set to any string.
/// Applies to AWS scenarios only.
// enos_user = "enos"

// ENTERPRISE ONLY
// Path to a license file
// boundary_license_path = "./support/boundary.hclic"
// Directly set the boundary license. Overrides boundary license file.
// boundary_license = ""

// ==============================================================================
// OPTIONAL VARIABLES
// ==============================================================================
// The path to the installation bundle for the target machines. The existing
// scenarios all use linux/amd64 architecture so bundle ought to match that
// architecture. This is only used for variants which use the `crt` builder
// variant. If you execute variants with the local builder this does not need
// to be set. In CI we use this to point to the artifacts generated as part
// of the build workflow.
// crt_bundle_path = "./boundary_linux_amd64.zip"

// Number of controller instances to create. Applies to AWS scenarios only.
// controller_count = 1

// Number of worker instances to create. Applies to AWS scenarios only.
// worker_count = 1

// Number of target instances to create. Applies to AWS scenarios only.
// target_count = 1

// The GCP project ID to use for the tests. Only needed if running GCP scenarios.
// gcp_project_id = "my-gcp-project-id"

// The GCP private_key_path. This is used to authenticate with GCP. Only needed
// if running GCP scenarios. This should not be used in combination with gcp_private_key.
// gcp_private_key_path = ""

// The GCP private_key. This is used to authenticate with GCP. Only needed
// if running GCP scenarios. This should not be used in combination with gcp_private_key_path.
// gcp_private_key = ""

// The GCP private_key_id. Only needed if running GCP scenarios.
// gcp_private_key_id = ""

// The GCP client_email used to authenticate with GCP
// gcp_client_email = "my-gcp-client-email"

// The directory that contains the copy of the boundary cli that the e2e tests
// will use in CI. Only needed if e2e_debug_no_run = false.
// local_boundary_dir = "/Users/<user>/.go/bin"

// The directory that contains the source code of boundary/boundary-enterprise.
// This is used in docker scenarios in CI in order to mount the source code into
// the container. Only needed if e2e_debug_no_run = false.
// local_boundary_src_dir = "/Users/<user>/Developer/boundary"

// The directory that contains the source code of boundary-ui. This is used for
// front-end e2e testing (UI scenarios) in CI. Only needed if e2e_debug_no_run = false.
// local_boundary_ui_src_dir = "/Users/<user>/Developer/boundary-ui"

// Github token to load go modules on windows client
// only required for running automation on RDP e2e test cases
// Token requires read access to hashicorp repositories
// github_token = ""

// The boundary version for the worker in scenarios with a worker and controller version
// mismatch. Will pull the official boundary docker image for given version.
// worker_version = "0.21"