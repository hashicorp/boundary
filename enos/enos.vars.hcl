# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

// Example variable inputs. Set these to valid values and uncomment them before
// running scenarios.

// The AWS region you want to create the resources in. Make sure you choose a
// region where you've got an AWS keypair.
// aws_region = "us-east-1"

// The name of the AWS keypair. You can look them up in the AWS console on a per-
// region basis. E.g. https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#KeyPairs:
// aws_ssh_keypair_name = "mykeypair"

// The path to the private key associated with your keypair.
// aws_ssh_private_key_path = "/Users/<user>/.ssh/mykeypair.pem

// The username to use for boundary. The github username of the user who trigger
// the workflow will be used automatically in the CI.
// enos_user = "enos"

// The directory that contains the copy of boundary you want to local execution
// from. `make install` should install it into the $GOBIN, which is usually
// similar to what is listed below.
// local_boundary_dir = "/Users/<user>/.go/bin"

// The directory that contains the copy of boundary you want to use for e2e tests
// local_boundary_src_dir = "/Users/<user>/Developer/boundary"

// The directory that contains the copy of boundary-ui you want to use for UI tests
// local_boundary_ui_src_dir = "/Users/<user>/Developer/boundary-ui"

// Path to a license file if required
// boundary_license_path = "./support/boundary.hclic"

// Built binary custom name, if not "boundary"
// boundary_binary_name = "boundary"

// Build edition from CRT
// boundary_edition = "oss"

// The path to the installation bundle for the target machines. The existing
// scenarios all use linux/amd64 architecture so bundle ought to match that
// architecture. This is only used for variants which use the `crt` builder
// variant. If you execute variants with the local builder this does not need
// to be set. In CI we use this to point to the artifacts generated as part
// of the build workflow.
// crt_bundle_path = "./boundary_linux_amd64.zip"

// The port the ALB will listen on to proxy controller API requests. This defaults
// to 9200
// alb_listener_api_port = 9200

// Generally, if there's failure in the test suite for any reason, enos/terraform will throw an error and you
// would not be able to access the environment variables needed to test locally. Enabling this
// will ensure that the enos scenario passes.
// e2e_debug_no_run = true

// Timeout for `go test` execution in the e2e tests, 10m default
// go_test_timeout = "10m"
