package pluginhost

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/stretchr/testify/require"

	// The packages below are used exclusively to get/set and encrypt/decrypt
	// host catalog secrets. See getHostCatalogSecrets and
	// removeSecretsCredsLastRotatedTime functions.
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// The tests in this file aim to provide a comprehensive exercise of AWS dynamic
// host catalog functionality. These tests are end-to-end in the sense that they
// act as regular Boundary clients, making requests to the API and expecting
// responses.

// All tests are designed to be run manually and are incompatible with CI as
// they expect a Boundary instance to already be running (as well as other
// setup/infrastructure). All tests expect one or more hosts that match the
// provided AWS `DescribeInstances` filter to be present in EC2. All tests are
// designed to be run sequentially - Parallelism is not supported.

// TestCommunityAwsDhc provides tests that should be run against a community
// edition Boundary instance. TestEnterpriseAwsDhc provides tests that should be
// run against an enterprise edition Boundary instance.

// Some of the tests in this file can be run against a simple `boundary dev`
// instance, however, some do not run by default as they need a special Boundary
// deployment to run (eg: `AssumeRole` tests require a Boundary controller and
// worker setup in AWS). The latter test cases are marked with the `skip: true`
// bool in their definition. To run these, set the `PLUGINHOST_TESTS_NO_SKIP`
// environment variable to any value. Note that this variable controls whether
// to skip tests globally.

// It is not advised to run all the tests at once with this variable set as it
// can lead to unexpected test case interactions. Instead, this variable is
// designed to allow running individual tests (ie: `PLUGINHOST_TESTS_NO_SKIP=1
// go test -run <test_name> ./...`). Each test case in this file is marked with
// the `go test` command to run it.

// All test cases are grouped by operation: create, update and delete. Each one
// of these sub-sets contains test cases that permutate through most if not all
// of the possible states for a given host catalog operation.

// Different tests require different Boundary set-ups. Broadly speaking, any
// test that concerns itself with static credentials (no rotation) can be run
// against a `boundary dev` instance. Any test that concerns itself with static
// credentials (with rotation) can also be run against a `boundary dev`
// instance, however, AWS imposes a 2 access key per IAM user limit, and
// credential rotation momentarily takes both of those slots up, so you'll need
// to verify only one access key is registered before running them. Any test
// that concerns itself with dynamic credentials (AssumeRole) requires a special
// Boundary setup in AWS. The most basic setup for this is 2 EC2 instances in a
// VPC, one running a controller, one running a PKI worker. The PKI worker EC2
// instance should then have an AWS role with the `AmazonEC2ReadOnlyAccess`
// policy set. For any test cases that set a worker filter, a running Boundary
// worker that satisfies the boolean expression must be present.

// In order to help with the aforementioned AWS access key limit, as well as
// destructive interactions between tests, the test code will grab persisted
// credentials from the running Boundary instance, decrypt them and reuse them
// in subsequent tests. This means the test must have access to the underlying
// Postgres instance that is in use by Boundary.

// Moreover, the update test suite will use this same functionality between the
// step of creating a host catalog and updating it, to facilitate credential
// rotation testing.

// Note that a database connection string is required (to connect to the
// database) for this functionality, as well as the Boundary AEAD root key (to
// encrypt/decrypt the secrets). See the environment variables section to learn
// more.

// At the end of the entire test run, the most recent set of AWS credentials
// will be printed so you can copy them and easily reset your environment for
// subsequent runs. Note that these can still be incorrect if the AWS plugin
// throws an error *after* rotating credentials. In this case, not even Boundary
// will know the rotated credentials and you'll have to go into the AWS IAM
// dashboard, delete the key(s), create a fresh one and then reset your
// environment.

// Environment variables are used to configure test functionality:
//
// * PLUGINHOST_TESTS_NO_SKIP: If set (to anything), the tests that are marked
//   to be skipped by default will run.
//
// * PLUGINHOST_TESTS_RUN: If set (to anything), runs the tests. This is a
//   global environment variable that prevents the tests from being run
//   automatically.
//
// * AWS_REGION: The region to set on the AWS host catalog. If not set, will
//   default to us-east-1.
//
// * AWS_ACCESS_KEY_ID: The access key id to set on the AWS host catalog.
//   Required for static credential test cases.
//
// * AWS_SECRET_ACCESS_KEY: The secret access key to set on the AWS host catalog
//   Required for static credential test cases.
//
// * AWS_ROLE_ARN: The role ARN to set on the AWS host catalog. Used in any test
//   cases that sets dynamic credentials (AssumeRole).
//
// * AWS_HOST_SET_FILTERS: The AWS `DescribeInstance` filters to set on the host
//   set. If not set, will default to "tag:type=prod".
//
// * BOUNDARY_WORKER_FILTER: The worker filter to be used in any tests that set
//   a host catalog worker filter. If not set, will default to
//   `"dev" in "/tags/type"`.
//
// * BOUNDARY_LOGIN_NAME: Boundary instance login name. Used to authenticate the
//   API client. If not set, will default to "admin".
//
// * BOUNDARY_PASSWORD: Boundary instance user password. Used to authenticate
//   the API client. If not set, will default to "password".
//
// * BOUNDARY_AUTHMETHOD_ID: Boundary auth method id. Used to authenticate the
//   API client. If not set, will default to "ampw_1234567890".
//
// * BOUNDARY_DB_CONN_STRING: A PostgreSQL connection string to the running
//   Boundary database. Used to get/set host catalog persisted secrets.
//   Format: postgresql://[user[:password]@][netloc][:port][/dbname].
//
// * BOUNDARY_AEAD_ROOT_KEY: Base64-encoded string representing the root key
//   bytes used in the running Boundary instance. Shown during Boundary startup
//   or in config file. Used to encrypt/decrypt host catalog persisted secrets.
//
// In addition to the above, any environment variables read directly by the
// Boundary API client (eg: BOUNDARY_ADDR, BOUNDARY_TOKEN) are also supported.

func TestCommunityAwsDhc(t *testing.T) {
	_, run := os.LookupEnv("PLUGINHOST_TESTS_RUN")
	if !run {
		t.Skip("TestCommunityAwsDhc is designed to only be run manually.")
	}

	_, forceNoSkip := os.LookupEnv("PLUGINHOST_TESTS_NO_SKIP")

	cl := authenticate(t)

	rw, k := dbKmsSetup(t)

	workerFilter := os.Getenv("BOUNDARY_WORKER_FILTER")
	if workerFilter == "" {
		t.Log("BOUNDARY_WORKER_FILTER not set, using default")
		workerFilter = `"dev" in "/tags/type"`
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		t.Log("AWS_REGION not set, using default")
		region = "us-east-1"
	}

	initialAwsAccessKeyId := os.Getenv("AWS_ACCESS_KEY_ID")
	if initialAwsAccessKeyId == "" {
		t.Log("AWS_ACCESS_KEY_ID not set, static credential tests could fail")
	}
	initialAwsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if initialAwsSecretAccessKey == "" {
		t.Log("AWS_SECRET_ACCESS_KEY not set, static credential tests could fail")
	}

	awsRoleArn := os.Getenv("AWS_ROLE_ARN")
	if awsRoleArn == "" {
		t.Log("AWS_ROLE_ARN not set, AssumeRole credential tests could fail")
	}

	staticAwsAttrs := map[string]any{
		"region":                      region,
		"disable_credential_rotation": true,
		"role_arn":                    "",
	}
	staticRotatedAwsAttrs := map[string]any{
		"region":                      region,
		"disable_credential_rotation": false,
		"role_arn":                    "",
	}
	assumeRoleAwsAttrs := map[string]any{
		"region":                      region,
		"disable_credential_rotation": true,
		"role_arn":                    awsRoleArn,
	}
	staticAwsSecrets := map[string]any{
		// The values in this map will be replaced over the course of the tests
		// with the most up-to-date persisted secrets from the database to
		// facilitate running more subsequent cases. At the end of execution,
		// the most up-to-date secrets stored in this map will be printed so
		// they can be reused in further runs. Note that this can still be
		// incorrect if the AWS plugin throws an error *after* rotating
		// credentials. In this case, not even Boundary will know the rotated
		// credentials and you'll have to go into the AWS IAM dashboard, delete
		// the rotated key, create a fresh one and then reset your environment.
		"access_key_id":     initialAwsAccessKeyId,
		"secret_access_key": initialAwsSecretAccessKey,
	}
	t.Cleanup(func() {
		t.Logf("Your AWS Access Key Id: %s", staticAwsSecrets["access_key_id"])
		t.Logf("Your AWS Secret Access Key: %s", staticAwsSecrets["secret_access_key"])
		if t.Failed() {
			t.Log("The tests failed - The credentials printed above may not exist anymore. Please check your AWS IAM dashboard.")
		}
	})

	hsFilters := make([]any, 0)
	hsFiltersStr := os.Getenv("AWS_HOST_SET_FILTERS")
	if hsFiltersStr != "" {
		hsFilters = append(hsFilters, strings.Split(hsFiltersStr, " "))
	} else {
		t.Log("AWS_FILTERS not set, continuing with default")
		hsFilters = append(hsFilters, "tag:type=prod")
	}
	hsAttrs := map[string]any{"filters": hsFilters}

	// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/create ./...
	t.Run("create", func(t *testing.T) {
		tests := []struct {
			name         string
			workerFilter string
			attrs        map[string]any
			secrets      *map[string]any
			expErrMsg    string
			skip         bool
		}{
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/create/staticCredentialsNoWorkerFilter
				name:    "staticCredentialsNoWorkerFilter",
				attrs:   staticAwsAttrs,
				secrets: &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/create/staticCredentialsWorkerFilter
				name:         "staticCredentialsWorkerFilter",
				workerFilter: workerFilter,
				attrs:        staticAwsAttrs,
				secrets:      &staticAwsSecrets,
				expErrMsg:    "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/create/staticCredentialsRotatedNoWorkerFilter
				name:    "staticCredentialsRotatedNoWorkerFilter",
				attrs:   staticRotatedAwsAttrs,
				secrets: &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/create/staticCredentialsRotatedWorkerFilter
				name:         "staticCredentialsRotatedWorkerFilter",
				workerFilter: workerFilter,
				attrs:        staticRotatedAwsAttrs,
				secrets:      &staticAwsSecrets,
				expErrMsg:    "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/create/assumeRoleCredentialsNoWorkerFilter
				name:  "assumeRoleCredentialsNoWorkerFilter",
				attrs: assumeRoleAwsAttrs,
				skip:  true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/create/assumeRoleCredentialsWorkerFilter
				name:         "assumeRoleCredentialsWorkerFilter",
				workerFilter: workerFilter,
				attrs:        assumeRoleAwsAttrs,
				expErrMsg:    "Worker filter on host catalogs is an Enterprise-only feature",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.skip && !forceNoSkip {
					t.Skip("Skipping because PLUGINHOST_TESTS_NO_SKIP is not set.")
				}

				name := fmt.Sprintf("%s/%s", t.Name(), randString(6))
				t.Logf("test run name is %q", name)

				_, projId := orgProjSetup(t, cl, name, false)

				hcOpts := []hostcatalogs.Option{
					hostcatalogs.WithPluginName("aws"),
					hostcatalogs.WithName(fmt.Sprintf("%s/hcplg", name)),
				}
				if len(tt.attrs) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithAttributes(tt.attrs))
				}
				if tt.secrets != nil && len(*tt.secrets) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithSecrets(*tt.secrets))
				}
				if tt.workerFilter != "" {
					hcOpts = append(hcOpts, hostcatalogs.WithWorkerFilter(tt.workerFilter))
				}

				hcl := hostcatalogs.NewClient(cl)
				hcrr, err := hcl.Create(context.Background(), "plugin", projId, hcOpts...)
				if tt.expErrMsg != "" {
					require.ErrorContains(t, err, tt.expErrMsg)
					require.Nil(t, hcrr)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, hcrr.GetItem())
				require.EqualValues(t, tt.attrs, hcrr.GetItem().Attributes)

				// Update credentials for next test.
				persistedSecrets := getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				hscl := hostsets.NewClient(cl)
				hsrr, err := hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr.GetItem())
				require.EqualValues(t, hsAttrs, hsrr.GetItem().Attributes)

				hs, err := pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, hsrr.GetItem().Version)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)
				t.Logf("hosts found in host set: %s", strings.Join(hs.HostIds, ", "))

				// Delete host set so that the set sync job doesn't continuously
				// error if/when current test credentials get deleted by another
				// test.
				_, err = hscl.Delete(context.Background(), hs.Id)
				require.NoError(t, err)
			})
		}
	})

	// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update ./...
	t.Run("update", func(t *testing.T) {
		type updWorkerFilter struct {
			remove bool
			value  string
		}
		type updAttrs struct {
			remove bool
			value  map[string]any
		}
		type updSecrets struct {
			remove bool
			value  *map[string]any
		}

		tests := []struct {
			name                string
			currentWorkerFilter string
			currentAttrs        map[string]any
			currentSecrets      *map[string]any
			newWorkerFilter     *updWorkerFilter
			newAttrs            *updAttrs
			newSecrets          *updSecrets
			expErrMsg           string
			preventCredDeletion bool
			skip                bool
		}{
			// Any credential type, no worker filter to any credential type with
			// worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticNoWorkerFilterToStaticWithWorkerFilter
				name:            "staticNoWorkerFilterToStaticWithWorkerFilter",
				currentAttrs:    staticAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticNoWorkerFilterToStaticRotatedWithWorkerFilter
				name:            "staticNoWorkerFilterToStaticRotatedWithWorkerFilter",
				currentAttrs:    staticAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: staticRotatedAwsAttrs},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticNoWorkerFilterToAssumeRoleWithWorkerFilter
				name:            "staticNoWorkerFilterToAssumeRoleWithWorkerFilter",
				currentAttrs:    staticAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:      &updSecrets{remove: true},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticRotatedNoWorkerFilterToStaticRotatedWithWorkerFilter
				name:            "staticRotatedNoWorkerFilterToStaticRotatedWithWorkerFilter",
				currentAttrs:    staticRotatedAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticRotatedNoWorkerFilterToStaticWithWorkerFilter
				name:            "staticRotatedNoWorkerFilterToStaticWithWorkerFilter",
				currentAttrs:    staticRotatedAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: staticAwsAttrs},
				newSecrets:      &updSecrets{value: &staticAwsSecrets},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticRotatedNoWorkerFilterToAssumeRoleWithWorkerFilter
				name:            "staticRotatedNoWorkerFilterToAssumeRoleWithWorkerFilter",
				currentAttrs:    staticRotatedAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:      &updSecrets{remove: true},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/update/assumeRoleNoWorkerFilterToAssumeRoleWithWorkerFilter
				name:            "assumeRoleNoWorkerFilterToAssumeRoleWithWorkerFilter",
				currentAttrs:    assumeRoleAwsAttrs,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
				skip:            true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/update/assumeRoleNoWorkerFilterToStaticWithWorkerFilter
				name:            "assumeRoleNoWorkerFilterToStaticWithWorkerFilter",
				currentAttrs:    assumeRoleAwsAttrs,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: staticAwsAttrs},
				newSecrets:      &updSecrets{value: &staticAwsSecrets},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
				skip:            true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/update/assumeRoleNoWorkerFilterToStaticRotatedWithWorkerFilter
				name:            "assumeRoleNoWorkerFilterToStaticRotatedWithWorkerFilter",
				currentAttrs:    assumeRoleAwsAttrs,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:      &updSecrets{value: &staticAwsSecrets},
				expErrMsg:       "Worker filter on host catalogs is an Enterprise-only feature",
				skip:            true,
			},

			// Static credentials no worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticNoWorkerFilterToStaticRotatedNoWorkerFilter
				name:           "staticNoWorkerFilterToStaticRotatedNoWorkerFilter",
				currentAttrs:   staticAwsAttrs,
				currentSecrets: &staticAwsSecrets,
				newAttrs:       &updAttrs{value: staticRotatedAwsAttrs},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/update/staticNoWorkerFilterToAssumeRoleNoWorkerFilter
				name:           "staticNoWorkerFilterToAssumeRoleNoWorkerFilter",
				currentAttrs:   staticAwsAttrs,
				currentSecrets: &staticAwsSecrets,
				newAttrs:       &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:     &updSecrets{remove: true},
				skip:           true,
			},

			// Static rotated credentials no worker permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/update/staticRotatedNoWorkerFilterToStaticNoWorkerFilter
				name:           "staticRotatedNoWorkerFilterToStaticNoWorkerFilter",
				currentAttrs:   staticRotatedAwsAttrs,
				currentSecrets: &staticAwsSecrets,
				newAttrs:       &updAttrs{value: staticAwsAttrs},
				newSecrets:     &updSecrets{value: &staticAwsSecrets},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/update/staticRotatedNoWorkerFilterToAssumeRoleNoWorkerFilter
				name:           "staticRotatedNoWorkerFilterToAssumeRoleNoWorkerFilter",
				currentAttrs:   staticRotatedAwsAttrs,
				currentSecrets: &staticAwsSecrets,
				newAttrs:       &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:     &updSecrets{remove: true},
				skip:           true,
			},

			// AssumeRole credentials no worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/update/assumeRoleNoWorkerFilterToStaticNoWorkerFilter
				name:         "assumeRoleNoWorkerFilterToStaticNoWorkerFilter",
				currentAttrs: assumeRoleAwsAttrs,
				newAttrs:     &updAttrs{value: staticAwsAttrs},
				newSecrets:   &updSecrets{value: &staticAwsSecrets},
				skip:         true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/update/assumeRoleNoWorkerFilterToStaticRotatedNoWorkerFilter
				name:         "assumeRoleNoWorkerFilterToStaticRotatedNoWorkerFilter",
				currentAttrs: assumeRoleAwsAttrs,
				newAttrs:     &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:   &updSecrets{value: &staticAwsSecrets},
				skip:         true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.skip && !forceNoSkip {
					t.SkipNow()
				}

				name := fmt.Sprintf("%s/%s", t.Name(), randString(6))
				t.Logf("test run name is %q", name)

				_, projId := orgProjSetup(t, cl, name, false)

				hcOpts := []hostcatalogs.Option{
					hostcatalogs.WithPluginName("aws"),
					hostcatalogs.WithName(fmt.Sprintf("%s/hcplg", name)),
				}
				if len(tt.currentAttrs) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithAttributes(tt.currentAttrs))
				}
				if tt.currentSecrets != nil && len(*tt.currentSecrets) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithSecrets(*tt.currentSecrets))
				}
				if tt.currentWorkerFilter != "" {
					hcOpts = append(hcOpts, hostcatalogs.WithWorkerFilter(tt.currentWorkerFilter))
				}

				hcl := hostcatalogs.NewClient(cl)
				hcrr, err := hcl.Create(context.Background(), "plugin", projId, hcOpts...)
				require.NoError(t, err)
				require.NotNil(t, hcrr)
				require.EqualValues(t, tt.currentAttrs, hcrr.GetItem().Attributes)
				if tt.currentWorkerFilter != "" {
					require.Equal(t, tt.currentWorkerFilter, hcrr.GetItem().WorkerFilter)
				}

				hscl := hostsets.NewClient(cl)
				hsrr, err := hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr.GetItem())
				require.EqualValues(t, hsAttrs, hsrr.GetItem().Attributes)

				// Obtain current secrets so we can reuse them later if needed.
				persistedSecrets := getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				hs, err := pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, hsrr.GetItem().Version)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)

				// Delete host set, update host catalog.
				_, err = hscl.Delete(context.Background(), hs.Id)
				require.NoError(t, err)

				hcUpdOpts := make([]hostcatalogs.Option, 0)
				if tt.newWorkerFilter != nil {
					if tt.newWorkerFilter.remove {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.DefaultWorkerFilter())
					} else {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.WithWorkerFilter(tt.newWorkerFilter.value))
					}
				}
				if tt.newAttrs != nil {
					if tt.newAttrs.remove {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.DefaultAttributes())
					} else {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.WithAttributes(tt.newAttrs.value))
					}
				}
				if tt.newSecrets != nil {
					if tt.newSecrets.remove {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.DefaultSecrets())
					} else {
						if tt.newSecrets.value != nil {
							hcUpdOpts = append(hcUpdOpts, hostcatalogs.WithSecrets(*tt.newSecrets.value))
						}
					}
				}

				if tt.preventCredDeletion {
					// On a test that goes from static rotated creds -> any,
					// prevent the keys from being deleted upon update.
					removeSecretsCredsLastRotatedTime(t, rw, k, hcrr.GetItem())
				}
				hcrr, err = hcl.Update(
					context.Background(),
					hcrr.GetItem().Id,
					hcrr.GetItem().Version,
					hcUpdOpts...,
				)
				if tt.expErrMsg != "" {
					require.ErrorContains(t, err, tt.expErrMsg)
					require.Nil(t, hcrr)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, hcrr.GetItem())
				if tt.newWorkerFilter != nil {
					if tt.newWorkerFilter.remove {
						require.Empty(t, hcrr.GetItem().WorkerFilter)
					} else {
						require.Equal(t, tt.newWorkerFilter.value, hcrr.GetItem().WorkerFilter)
					}
				}
				if tt.newAttrs != nil {
					if tt.newAttrs.remove {
						require.Empty(t, hcrr.GetItem().Attributes)
					} else {
						require.EqualValues(t, tt.newAttrs.value, hcrr.GetItem().Attributes)
					}
				}

				// Obtain current secrets for next test cases.
				persistedSecrets = getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				// Create new host set against updated host catalog. Verify
				// success.
				hsrr, err = hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr.GetItem())
				require.EqualValues(t, hsAttrs, hsrr.GetItem().Attributes)

				hs, err = pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, hsrr.GetItem().Version)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)
				t.Logf("hosts found in host set: %s", strings.Join(hs.HostIds, ", "))

				// Delete host set so that the set sync job doesn't continuously
				// error if/when current test credentials get deleted by another
				// test.
				_, err = hscl.Delete(context.Background(), hs.Id)
				require.NoError(t, err)
			})
		}
	})

	// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/delete ./...
	t.Run("delete", func(t *testing.T) {
		tests := []struct {
			name                string
			attrs               map[string]any
			secrets             *map[string]any
			preventCredDeletion bool
			skip                bool
		}{
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/delete/staticCredentials
				name:    "staticCredentials",
				attrs:   staticAwsAttrs,
				secrets: &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestCommunityAwsDhc/delete/staticRotatedCredentials
				name:                "staticRotatedCredentials",
				attrs:               staticRotatedAwsAttrs,
				secrets:             &staticAwsSecrets,
				preventCredDeletion: true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestCommunityAwsDhc/delete/assumeRoleCredentials
				name:  "assumeRoleCredentials",
				attrs: assumeRoleAwsAttrs,
				skip:  true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.skip && !forceNoSkip {
					t.SkipNow()
				}

				name := fmt.Sprintf("%s/%s", t.Name(), randString(6))
				t.Logf("test run name is %q", name)

				_, projId := orgProjSetup(t, cl, name, false)

				hcOpts := []hostcatalogs.Option{
					hostcatalogs.WithPluginName("aws"),
					hostcatalogs.WithName(fmt.Sprintf("%s/hcplg", name)),
				}
				if len(tt.attrs) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithAttributes(tt.attrs))
				}
				if tt.secrets != nil && len(*tt.secrets) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithSecrets(*tt.secrets))
				}

				hcl := hostcatalogs.NewClient(cl)
				hcrr, err := hcl.Create(context.Background(), "plugin", projId, hcOpts...)
				require.NoError(t, err)
				require.NotNil(t, hcrr)

				// Update credentials for next test.
				persistedSecrets := getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				hscl := hostsets.NewClient(cl)
				hsrr, err := hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr)

				hs, err := pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, 0)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)
				t.Logf("hosts found in host set: %s", strings.Join(hs.HostIds, ", "))

				if tt.preventCredDeletion {
					// On a test that deletes a host catalog using static
					// rotated creds, prevent the keys from being deleted upon
					// deletion.
					removeSecretsCredsLastRotatedTime(t, rw, k, hcrr.GetItem())
				}

				_, err = hcl.Delete(context.Background(), hcrr.GetItem().Id)
				require.NoError(t, err)
			})
		}
	})
}

func TestEnterpriseAwsDhc(t *testing.T) {
	_, run := os.LookupEnv("PLUGINHOST_TESTS_RUN")
	if !run {
		t.Skip("TestEnterpriseAwsDhc is designed to only be run manually.")
	}

	_, forceNoSkip := os.LookupEnv("PLUGINHOST_TESTS_NO_SKIP")

	cl := authenticate(t)

	rw, k := dbKmsSetup(t)

	workerFilter := os.Getenv("BOUNDARY_WORKER_FILTER")
	if workerFilter == "" {
		t.Log("BOUNDARY_WORKER_FILTER not set, using default")
		workerFilter = `"dev" in "/tags/type"`
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		t.Log("AWS_REGION not set, using default")
		region = "us-east-1"
	}

	initialAwsAccessKeyId := os.Getenv("AWS_ACCESS_KEY_ID")
	if initialAwsAccessKeyId == "" {
		t.Log("AWS_ACCESS_KEY_ID not set, static credential tests could fail")
	}
	initialAwsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if initialAwsSecretAccessKey == "" {
		t.Log("AWS_SECRET_ACCESS_KEY not set, static credential tests could fail")
	}

	awsRoleArn := os.Getenv("AWS_ROLE_ARN")
	if awsRoleArn == "" {
		t.Log("AWS_ROLE_ARN not set, AssumeRole credential tests could fail")
	}

	staticAwsAttrs := map[string]any{
		"region":                      region,
		"disable_credential_rotation": true,
		"role_arn":                    "",
	}
	staticRotatedAwsAttrs := map[string]any{
		"region":                      region,
		"disable_credential_rotation": false,
		"role_arn":                    "",
	}
	assumeRoleAwsAttrs := map[string]any{
		"region":                      region,
		"disable_credential_rotation": true,
		"role_arn":                    awsRoleArn,
	}
	staticAwsSecrets := map[string]any{
		// The values in this map will be replaced over the course of the tests
		// with the most up-to-date persisted secrets from the database to
		// facilitate running more test cases. At the end of execution, the most
		// up-to-date secrets stored in this variable will be printed so they
		// can be reused in further runs. Note that this can still be incorrect
		// if the AWS plugin throws an error *after* rotating credentials. In
		// this case, not even Boundary will know the rotated credentials and
		// you'll have to go into the AWS IAM dashboard, delete the rotated key,
		// create a fresh one and then reset your environment.
		"access_key_id":     initialAwsAccessKeyId,
		"secret_access_key": initialAwsSecretAccessKey,
	}
	t.Cleanup(func() {
		t.Logf("Your AWS Access Key Id: %s", staticAwsSecrets["access_key_id"])
		t.Logf("Your AWS Secret Access Key: %s", staticAwsSecrets["secret_access_key"])
		if t.Failed() {
			t.Log("The tests failed - The credentials printed above may not exist anymore. Please check your AWS IAM dashboard.")
		}
	})

	hsFilters := make([]any, 0)
	hsFiltersStr := os.Getenv("AWS_HOST_SET_FILTERS")
	if hsFiltersStr != "" {
		hsFilters = append(hsFilters, strings.Split(hsFiltersStr, " "))
	} else {
		t.Log("AWS_FILTERS not set, continuing with default")
		hsFilters = append(hsFilters, "tag:type=prod")
	}
	hsAttrs := map[string]any{"filters": hsFilters}

	// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/create ./...
	t.Run("create", func(t *testing.T) {
		tests := []struct {
			name         string
			workerFilter string
			attrs        map[string]any
			secrets      *map[string]any
			skip         bool
		}{
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/create/staticCredentialsNoWorkerFilter
				name:    "staticCredentialsNoWorkerFilter",
				attrs:   staticAwsAttrs,
				secrets: &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/create/staticCredentialsWorkerFilter
				name:         "staticCredentialsWorkerFilter",
				workerFilter: workerFilter,
				attrs:        staticAwsAttrs,
				secrets:      &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/create/staticCredentialsRotatedNoWorkerFilter
				name:    "staticCredentialsRotatedNoWorkerFilter",
				attrs:   staticRotatedAwsAttrs,
				secrets: &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/create/staticCredentialsRotatedWorkerFilter
				name:         "staticCredentialsRotatedWorkerFilter",
				workerFilter: workerFilter,
				attrs:        staticRotatedAwsAttrs,
				secrets:      &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/create/assumeRoleCredentialsNoWorkerFilter
				name:  "assumeRoleCredentialsNoWorkerFilter",
				attrs: assumeRoleAwsAttrs,
				skip:  true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/create/assumeRoleCredentialsWorkerFilter
				name:         "assumeRoleCredentialsWorkerFilter",
				workerFilter: workerFilter,
				attrs:        assumeRoleAwsAttrs,
				skip:         true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.skip && !forceNoSkip {
					t.Skip("Skipping because PLUGINHOST_TESTS_NO_SKIP is not set.")
				}

				name := fmt.Sprintf("%s/%s", t.Name(), randString(6))
				t.Logf("test run name is %q", name)

				_, projId := orgProjSetup(t, cl, name, false)

				hcOpts := []hostcatalogs.Option{
					hostcatalogs.WithPluginName("aws"),
					hostcatalogs.WithName(fmt.Sprintf("%s/hcplg", name)),
				}
				if len(tt.attrs) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithAttributes(tt.attrs))
				}
				if tt.secrets != nil && len(*tt.secrets) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithSecrets(*tt.secrets))
				}
				if tt.workerFilter != "" {
					hcOpts = append(hcOpts, hostcatalogs.WithWorkerFilter(tt.workerFilter))
				}

				hcl := hostcatalogs.NewClient(cl)
				hcrr, err := hcl.Create(context.Background(), "plugin", projId, hcOpts...)
				require.NoError(t, err)
				require.NotNil(t, hcrr.GetItem())
				require.EqualValues(t, tt.attrs, hcrr.GetItem().Attributes)
				if tt.workerFilter != "" {
					require.Equal(t, tt.workerFilter, hcrr.GetItem().WorkerFilter)
				}

				// Update credentials for next test.
				persistedSecrets := getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				hscl := hostsets.NewClient(cl)
				hsrr, err := hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr.GetItem())
				require.EqualValues(t, hsAttrs, hsrr.GetItem().Attributes)

				hs, err := pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, hsrr.GetItem().Version)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)
				t.Logf("hosts found in host set: %s", strings.Join(hs.HostIds, ", "))

				// Delete host set so that the set sync job doesn't continuously
				// error if/when current test credentials get deleted by another
				// test.
				_, err = hscl.Delete(context.Background(), hs.Id)
				require.NoError(t, err)
			})
		}
	})

	// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update ./...
	t.Run("update", func(t *testing.T) {
		type updWorkerFilter struct {
			remove bool
			value  string
		}
		type updAttrs struct {
			remove bool
			value  map[string]any
		}
		type updSecrets struct {
			remove bool
			value  *map[string]any
		}

		tests := []struct {
			name                string
			currentWorkerFilter string
			currentAttrs        map[string]any
			currentSecrets      *map[string]any
			newWorkerFilter     *updWorkerFilter
			newAttrs            *updAttrs
			newSecrets          *updSecrets
			preventCredDeletion bool
			skip                bool
		}{
			// Static no worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticNoWorkerFilterToStaticWithWorkerFilter
				name:            "staticNoWorkerFilterToStaticWithWorkerFilter",
				currentAttrs:    staticAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticNoWorkerFilterToStaticRotatedNoWorkerFilter
				name:           "staticNoWorkerFilterToStaticRotatedNoWorkerFilter",
				currentAttrs:   staticAwsAttrs,
				currentSecrets: &staticAwsSecrets,
				newAttrs:       &updAttrs{value: staticRotatedAwsAttrs},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticNoWorkerFilterToStaticRotatedWithWorkerFilter
				name:            "staticNoWorkerFilterToStaticRotatedWithWorkerFilter",
				currentAttrs:    staticAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: staticRotatedAwsAttrs},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticNoWorkerFilterToAssumeRoleNoWorkerFilter
				name:           "staticNoWorkerFilterToAssumeRoleNoWorkerFilter",
				currentAttrs:   staticAwsAttrs,
				currentSecrets: &staticAwsSecrets,
				newAttrs:       &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:     &updSecrets{remove: true},
				skip:           true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticNoWorkerFilterToAssumeRoleWithWorkerFilter
				name:            "staticNoWorkerFilterToAssumeRoleWithWorkerFilter",
				currentAttrs:    staticAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:      &updSecrets{remove: true},
				skip:            true,
			},

			// Static with worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticWithWorkerFilterToStaticNoWorkerFilter
				name:                "staticWithWorkerFilterToStaticNoWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{remove: true},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticWithWorkerFilterToStaticRotatedNoWorkerFilter
				name:                "staticWithWorkerFilterToStaticRotatedNoWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{remove: true},
				newAttrs:            &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticWithWorkerFilterToStaticRotatedWithWorkerFilter
				name:                "staticWithWorkerFilterToStaticRotatedWithWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newAttrs:            &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticWithWorkerFilterToAssumeRoleNoWorkerFilter
				name:                "staticWithWorkerFilterToAssumeRoleNoWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{remove: true},
				newAttrs:            &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:          &updSecrets{remove: true},
				skip:                true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticWithWorkerFilterToAssumeRoleWithWorkerFilter
				name:                "staticWithWorkerFilterToAssumeRoleWithWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newAttrs:            &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:          &updSecrets{remove: true},
				skip:                true,
			},

			// Static rotated no worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedNoWorkerFilterToStaticRotatedWithWorkerFilter
				name:            "staticRotatedNoWorkerFilterToStaticRotatedWithWorkerFilter",
				currentAttrs:    staticRotatedAwsAttrs,
				currentSecrets:  &staticAwsSecrets,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedNoWorkerFilterToStaticNoWorkerFilter
				name:                "staticRotatedNoWorkerFilterToStaticNoWorkerFilter",
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newAttrs:            &updAttrs{value: staticAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				preventCredDeletion: true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedNoWorkerFilterToStaticWithWorkerFilter
				name:                "staticRotatedNoWorkerFilterToStaticWithWorkerFilter",
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{value: workerFilter},
				newAttrs:            &updAttrs{value: staticAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				preventCredDeletion: true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedNoWorkerFilterToAssumeRoleNoWorkerFilter
				name:                "staticRotatedNoWorkerFilterToAssumeRoleNoWorkerFilter",
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newAttrs:            &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:          &updSecrets{remove: true},
				preventCredDeletion: true,
				skip:                true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedNoWorkerFilterToAssumeRoleWithWorkerFilter
				name:                "staticRotatedNoWorkerFilterToAssumeRoleWithWorkerFilter",
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{value: workerFilter},
				newAttrs:            &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:          &updSecrets{remove: true},
				preventCredDeletion: true,
				skip:                true,
			},

			// Static rotated with worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedWithWorkerFilterToStaticRotatedNoWorkerFilter
				name:                "staticRotatedWithWorkerFilterToStaticRotatedNoWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{remove: true},
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedWithWorkerFilterToStaticNoWorkerFilter
				name:                "staticRotatedWithWorkerFilterToStaticNoWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{remove: true},
				newAttrs:            &updAttrs{value: staticAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				preventCredDeletion: true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedWithWorkerFilterToStaticWithWorkerFilter
				name:                "staticRotatedWithWorkerFilterToStaticWithWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newAttrs:            &updAttrs{value: staticAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				preventCredDeletion: true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedWithWorkerFilterToAssumeRoleNoWorkerFilter
				name:                "staticRotatedWithWorkerFilterToAssumeRoleNoWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newWorkerFilter:     &updWorkerFilter{remove: true},
				newAttrs:            &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:          &updSecrets{remove: true},
				preventCredDeletion: true,
				skip:                true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/staticRotatedWithWorkerFilterToAssumeRoleWithWorkerFilter
				name:                "staticRotatedWithWorkerFilterToAssumeRoleWithWorkerFilter",
				currentWorkerFilter: workerFilter,
				currentAttrs:        staticRotatedAwsAttrs,
				currentSecrets:      &staticAwsSecrets,
				newAttrs:            &updAttrs{value: assumeRoleAwsAttrs},
				newSecrets:          &updSecrets{remove: true},
				preventCredDeletion: true,
				skip:                true,
			},

			// AssumeRole no worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleNoWorkerFilterToAssumeRoleWithWorkerFilter
				name:            "assumeRoleNoWorkerFilterToAssumeRoleWithWorkerFilter",
				currentAttrs:    assumeRoleAwsAttrs,
				currentSecrets:  nil,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				skip:            true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleNoWorkerFilterToStaticNoWorkerFilter
				name:           "assumeRoleNoWorkerFilterToStaticNoWorkerFilter",
				currentAttrs:   assumeRoleAwsAttrs,
				currentSecrets: nil,
				newAttrs:       &updAttrs{value: staticAwsAttrs},
				newSecrets:     &updSecrets{value: &staticAwsSecrets},
				skip:           true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleNoWorkerFilterToStaticWithWorkerFilter
				name:            "assumeRoleNoWorkerFilterToStaticWithWorkerFilter",
				currentAttrs:    assumeRoleAwsAttrs,
				currentSecrets:  nil,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: staticAwsAttrs},
				newSecrets:      &updSecrets{value: &staticAwsSecrets},
				skip:            true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleNoWorkerFilterToStaticRotatedNoWorkerFilter
				name:           "assumeRoleNoWorkerFilterToStaticRotatedNoWorkerFilter",
				currentAttrs:   assumeRoleAwsAttrs,
				currentSecrets: nil,
				newAttrs:       &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:     &updSecrets{value: &staticAwsSecrets},
				skip:           true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleNoWorkerFilterToStaticRotatedWithWorkerFilter
				name:            "assumeRoleNoWorkerFilterToStaticRotatedWithWorkerFilter",
				currentAttrs:    assumeRoleAwsAttrs,
				currentSecrets:  nil,
				newWorkerFilter: &updWorkerFilter{value: workerFilter},
				newAttrs:        &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:      &updSecrets{value: &staticAwsSecrets},
				skip:            true,
			},

			// AssumeRole with worker filter permutations.
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleWithWorkerFilterToAssumeRoleNoWorkerFilter
				name:                "assumeRoleWithWorkerFilterToAssumeRoleNoWorkerFilter",
				currentAttrs:        assumeRoleAwsAttrs,
				currentSecrets:      nil,
				currentWorkerFilter: workerFilter,
				newWorkerFilter:     &updWorkerFilter{remove: true},
				skip:                true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleWithWorkerFilterToStaticNoWorkerFilter
				name:                "assumeRoleWithWorkerFilterToStaticNoWorkerFilter",
				currentAttrs:        assumeRoleAwsAttrs,
				currentSecrets:      nil,
				currentWorkerFilter: workerFilter,
				newWorkerFilter:     &updWorkerFilter{remove: true},
				newAttrs:            &updAttrs{value: staticAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				skip:                true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 gPLUGINHOST_TESTS_NO_SKIP=1 o test -v -run TestEnterpriseAwsDhc/update/assumeRoleWithWorkerFilterToStaticWithWorkerFilter
				name:                "assumeRoleWithWorkerFilterToStaticWithWorkerFilter",
				currentAttrs:        assumeRoleAwsAttrs,
				currentSecrets:      nil,
				currentWorkerFilter: workerFilter,
				newAttrs:            &updAttrs{value: staticAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				skip:                true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleWithWorkerFilterToStaticRotatedNoWorkerFilter
				name:                "assumeRoleWithWorkerFilterToStaticRotatedNoWorkerFilter",
				currentAttrs:        assumeRoleAwsAttrs,
				currentSecrets:      nil,
				currentWorkerFilter: workerFilter,
				newWorkerFilter:     &updWorkerFilter{remove: true},
				newAttrs:            &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				skip:                true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/update/assumeRoleWithWorkerFilterToStaticRotatedWithWorkerFilter
				name:                "assumeRoleWithWorkerFilterToStaticRotatedWithWorkerFilter",
				currentAttrs:        assumeRoleAwsAttrs,
				currentSecrets:      nil,
				currentWorkerFilter: workerFilter,
				newAttrs:            &updAttrs{value: staticRotatedAwsAttrs},
				newSecrets:          &updSecrets{value: &staticAwsSecrets},
				skip:                true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.skip && !forceNoSkip {
					t.SkipNow()
				}

				name := fmt.Sprintf("%s/%s", t.Name(), randString(6))
				t.Logf("test run name is %q", name)

				_, projId := orgProjSetup(t, cl, name, false)

				hcOpts := []hostcatalogs.Option{
					hostcatalogs.WithPluginName("aws"),
					hostcatalogs.WithName(fmt.Sprintf("%s/hcplg", name)),
				}
				if len(tt.currentAttrs) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithAttributes(tt.currentAttrs))
				}
				if tt.currentSecrets != nil && len(*tt.currentSecrets) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithSecrets(*tt.currentSecrets))
				}
				if tt.currentWorkerFilter != "" {
					hcOpts = append(hcOpts, hostcatalogs.WithWorkerFilter(tt.currentWorkerFilter))
				}

				hcl := hostcatalogs.NewClient(cl)
				hcrr, err := hcl.Create(context.Background(), "plugin", projId, hcOpts...)
				require.NoError(t, err)
				require.NotNil(t, hcrr)
				require.EqualValues(t, tt.currentAttrs, hcrr.GetItem().Attributes)
				if tt.currentWorkerFilter != "" {
					require.Equal(t, tt.currentWorkerFilter, hcrr.GetItem().WorkerFilter)
				}

				hscl := hostsets.NewClient(cl)
				hsrr, err := hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr.GetItem())
				require.EqualValues(t, hsAttrs, hsrr.GetItem().Attributes)

				// Obtain current secrets so we can reuse them later if needed.
				persistedSecrets := getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				hs, err := pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, hsrr.GetItem().Version)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)

				// Delete host set, update host catalog.
				_, err = hscl.Delete(context.Background(), hs.Id)
				require.NoError(t, err)

				hcUpdOpts := make([]hostcatalogs.Option, 0)
				if tt.newWorkerFilter != nil {
					if tt.newWorkerFilter.remove {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.DefaultWorkerFilter())
					} else {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.WithWorkerFilter(tt.newWorkerFilter.value))
					}
				}
				if tt.newAttrs != nil {
					if tt.newAttrs.remove {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.DefaultAttributes())
					} else {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.WithAttributes(tt.newAttrs.value))
					}
				}
				if tt.newSecrets != nil {
					if tt.newSecrets.remove {
						hcUpdOpts = append(hcUpdOpts, hostcatalogs.DefaultSecrets())
					} else {
						if tt.newSecrets.value != nil {
							hcUpdOpts = append(hcUpdOpts, hostcatalogs.WithSecrets(*tt.newSecrets.value))
						}
					}
				}

				if tt.preventCredDeletion {
					// On a test that goes from static rotated creds -> any,
					// prevent the keys from being deleted upon update.
					removeSecretsCredsLastRotatedTime(t, rw, k, hcrr.GetItem())
				}
				hcrr, err = hcl.Update(
					context.Background(),
					hcrr.GetItem().Id,
					hcrr.GetItem().Version,
					hcUpdOpts...,
				)
				require.NoError(t, err)
				require.NotNil(t, hcrr.GetItem())
				if tt.newWorkerFilter != nil {
					if tt.newWorkerFilter.remove {
						require.Empty(t, hcrr.GetItem().WorkerFilter)
					} else {
						require.Equal(t, tt.newWorkerFilter.value, hcrr.GetItem().WorkerFilter)
					}
				}
				if tt.newAttrs != nil {
					if tt.newAttrs.remove {
						require.Empty(t, hcrr.GetItem().Attributes)
					} else {
						require.EqualValues(t, tt.newAttrs.value, hcrr.GetItem().Attributes)
					}
				}

				// Obtain current secrets for next test cases.
				persistedSecrets = getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				// Create new host set against updated host catalog. Verify
				// success.
				hsrr, err = hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr.GetItem())
				require.EqualValues(t, hsAttrs, hsrr.GetItem().Attributes)

				hs, err = pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, hsrr.GetItem().Version)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)
				t.Logf("hosts found in host set: %s", strings.Join(hs.HostIds, ", "))

				// Delete host set so that the set sync job doesn't continuously
				// error if/when current test credentials get deleted by another
				// test.
				_, err = hscl.Delete(context.Background(), hs.Id)
				require.NoError(t, err)
			})
		}
	})

	// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/delete ./...
	t.Run("delete", func(t *testing.T) {
		tests := []struct {
			name                string
			workerFilter        string
			attrs               map[string]any
			secrets             *map[string]any
			preventCredDeletion bool
			skip                bool
		}{
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/delete/staticCredentialsNoWorkerFilter
				name:    "staticCredentialsNoWorkerFilter",
				attrs:   staticAwsAttrs,
				secrets: &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/delete/staticCredentialsWorkerFilter
				name:         "staticCredentialsWorkerFilter",
				workerFilter: workerFilter,
				attrs:        staticAwsAttrs,
				secrets:      &staticAwsSecrets,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/delete/staticCredentialsRotatedNoWorkerFilter
				name:                "staticCredentialsRotatedNoWorkerFilter",
				attrs:               staticRotatedAwsAttrs,
				secrets:             &staticAwsSecrets,
				preventCredDeletion: true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 go test -v -run TestEnterpriseAwsDhc/delete/staticCredentialsRotatedWorkerFilter
				name:                "staticCredentialsRotatedWorkerFilter",
				workerFilter:        workerFilter,
				attrs:               staticRotatedAwsAttrs,
				secrets:             &staticAwsSecrets,
				preventCredDeletion: true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/delete/assumeRoleCredentialsNoWorkerFilter
				name:  "assumeRoleCredentialsNoWorkerFilter",
				attrs: assumeRoleAwsAttrs,
				skip:  true,
			},
			{
				// PLUGINHOST_TESTS_RUN=1 PLUGINHOST_TESTS_NO_SKIP=1 go test -v -run TestEnterpriseAwsDhc/delete/assumeRoleCredentialsWorkerFilter
				name:         "assumeRoleCredentialsWorkerFilter",
				workerFilter: workerFilter,
				attrs:        assumeRoleAwsAttrs,
				skip:         true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.skip && !forceNoSkip {
					t.SkipNow()
				}

				name := fmt.Sprintf("%s/%s", t.Name(), randString(6))
				t.Logf("test run name is %q", name)

				_, projId := orgProjSetup(t, cl, name, false)

				hcOpts := []hostcatalogs.Option{
					hostcatalogs.WithPluginName("aws"),
					hostcatalogs.WithName(fmt.Sprintf("%s/hcplg", name)),
				}
				if len(tt.attrs) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithAttributes(tt.attrs))
				}
				if tt.secrets != nil && len(*tt.secrets) > 0 {
					hcOpts = append(hcOpts, hostcatalogs.WithSecrets(*tt.secrets))
				}
				if tt.workerFilter != "" {
					hcOpts = append(hcOpts, hostcatalogs.WithWorkerFilter(tt.workerFilter))
				}

				hcl := hostcatalogs.NewClient(cl)
				hcrr, err := hcl.Create(context.Background(), "plugin", projId, hcOpts...)
				require.NoError(t, err)
				require.NotNil(t, hcrr)
				if tt.workerFilter != "" {
					require.Equal(t, tt.workerFilter, hcrr.GetItem().WorkerFilter)
				}

				// Update credentials for next test.
				persistedSecrets := getHostCatalogSecrets(t, rw, k, hcrr.GetItem())
				if len(persistedSecrets.AsMap()) > 0 {
					staticAwsSecrets = persistedSecrets.AsMap()
				}

				hscl := hostsets.NewClient(cl)
				hsrr, err := hscl.Create(
					context.Background(),
					hcrr.GetItem().Id,
					hostsets.WithAttributes(hsAttrs),
				)
				require.NoError(t, err)
				require.NotNil(t, hsrr)

				hs, err := pollForSetSyncJobFinish(t, hscl, hsrr.GetItem().Id, 0)()
				require.NoError(t, err)
				require.NotNil(t, hs)
				require.NotEmpty(t, hs.HostIds)
				t.Logf("hosts found in host set: %s", strings.Join(hs.HostIds, ", "))

				if tt.preventCredDeletion {
					// On a test that deletes a host catalog using static
					// rotated creds, prevent the keys from being deleted upon
					// deletion.
					removeSecretsCredsLastRotatedTime(t, rw, k, hcrr.GetItem())
				}

				_, err = hcl.Delete(context.Background(), hcrr.GetItem().Id)
				require.NoError(t, err)
			})
		}
	})
}

func authenticate(t *testing.T) *api.Client {
	c, err := api.DefaultConfig()
	require.NoError(t, err, "authenticate: failed to get Boundary API client default config")

	cl, err := api.NewClient(c)
	require.NoError(t, err, "authenticate: failed to create new Boundary API client")

	if cl.Token() != "" {
		// Token present, assume the client is already authenticated.
		return cl
	}

	t.Log("no token found in api client, attempting authentication")

	ln := os.Getenv("BOUNDARY_LOGIN_NAME")
	if ln == "" {
		t.Log("BOUNDARY_LOGIN_NAME not set, using dev default")
		ln = "admin"
	}
	pw := os.Getenv("BOUNDARY_PASSWORD")
	if pw == "" {
		t.Log("BOUNDARY_PASSWORD not set, using dev default")
		pw = "password"
	}
	amid := os.Getenv("BOUNDARY_AUTHMETHOD_ID")
	if amid == "" {
		t.Log("BOUNDARY_AUTHMETHOD_ID not set, using dev default")
		amid = "ampw_1234567890"
	}

	amcl := authmethods.NewClient(cl)
	ar, err := amcl.Authenticate(
		context.Background(),
		amid,
		"login",
		map[string]any{"login_name": ln, "password": pw},
	)
	require.NoError(t, err, "authenticate: failed to authenticate client with Boundary")
	require.NotNil(t, ar, "authenticate: authenticate success but response was empty")

	at, err := ar.GetAuthToken()
	require.NoError(t, err, "authenticate: failed to get auth token")
	require.NotNil(t, ar, "authenticate: auth token retrieval successful but response was empty")
	require.NotEmpty(t, at.Token, "authenticate: auth token retrieval successful but no token found in response")

	cl.SetToken(at.Token)

	return cl
}

func dbKmsSetup(t *testing.T) (*db.Db, *kms.Kms) {
	ctx := context.Background()

	dbConnStr := os.Getenv("BOUNDARY_DB_CONN_STRING")
	require.NotEmpty(t, dbConnStr, "dbKmsSetup: required BOUNDARY_DB_CONN_STRING not set")

	// Base64-encoded string representing the AEAD key bytes (displayed during
	// Boundary startup or in config).
	rootKeyStr := os.Getenv("BOUNDARY_AEAD_ROOT_KEY")
	require.NotEmpty(t, rootKeyStr, "dbKmsSetup: required BOUNDARY_AEAD_ROOT_KEY not set")

	dbConn, err := db.Open(ctx, db.Postgres, dbConnStr)
	require.NoError(t, err, "dbKmsSetup: failed to open postgres database")
	t.Cleanup(func() { _ = dbConn.Close(ctx) })

	rw := db.New(dbConn)

	k, err := kms.New(ctx, rw, rw)
	require.NoError(t, err, "dbKmsSetup: failed to create new kms")

	rootKeyBytes, err := base64.StdEncoding.DecodeString(rootKeyStr)
	require.NoError(t, err, "dbKmsSetup: failed to decode root key %q as base64", rootKeyStr)

	aeadWrapper := aead.NewWrapper()
	_, err = aeadWrapper.SetConfig(ctx, wrapping.WithKeyId(rootKeyStr))
	require.NoError(t, err, "dbKmsSetup: failed to set key id %q into aead wrapper", rootKeyStr)

	require.NoError(t, aeadWrapper.SetAesGcmKeyBytes(rootKeyBytes), "dbKmsSetup: failed to set key bytes into aead wrapper")
	require.NoError(t, k.AddExternalWrappers(ctx, kms.WithRootWrapper(aeadWrapper)), "dbKmsSetup: failed to add aead wrapper to kms")

	return rw, k
}

func orgProjSetup(t *testing.T, cl *api.Client, name string, deleteAfterTest bool) (orgId, projId string) {
	scl := scopes.NewClient(cl)

	srr, err := scl.Create(context.Background(), "global", scopes.WithName(fmt.Sprintf("%s/org", name)))
	require.NoError(t, err, "orgProjSetup: failed to create org scope")
	require.NotNil(t, srr, "orgProjSetup: org scope creation successful but response was empty")

	orgId = srr.GetItem().Id
	require.NotEmpty(t, orgId, "orgProjSetup: failed to get org scope id from Boundary")

	srr, err = scl.Create(context.Background(), srr.GetItem().Id, scopes.WithName(fmt.Sprintf("%s/proj", name)))
	require.NoError(t, err, "orgProjSetup: failed to create project scope under %q", orgId)
	require.NotNil(t, srr, "orgProjSetup: project scope creation successful but response was empty")

	projId = srr.GetItem().Id
	require.NotEmpty(t, projId, "orgProjSetup: failed to get project scope id from Boundary")

	if deleteAfterTest {
		t.Cleanup(func() {
			scl := scopes.NewClient(cl)
			_, err := scl.Delete(context.Background(), orgId)
			if err != nil {
				t.Logf("orgProjSetup: failed to delete org id %q: %v", orgId, err)
			}
		})
	}
	return
}

func pollForSetSyncJobFinish(t *testing.T, hscl *hostsets.Client, hsId string, hsCurrentVersion uint32) func() (*hostsets.HostSet, error) {
	// When host set sync runs, it updates host set resources in the database.
	// We can poll for this by checking the resource's version field and
	// assuming the job is complete when that is incremented. This function
	// assumes that no other calls that update host set (hsId) occur during the
	// time pollFn is running as this will inherently update the host set
	// version.

	// Get current host set version.
	initialVersion := hsCurrentVersion
	if initialVersion == 0 {
		rsp, err := hscl.Read(context.Background(), hsId)
		require.NoError(t, err, "pollForSetSyncJobFinish: failed to read host set %q", hsId)
		require.NotNil(t, rsp, "pollForSetSyncJobFinish: read host set %q successful but got empty response", hsId)
		require.NotZero(t, rsp.GetItem().Version, "pollForSetSyncJobFinish: unexpected host set %q version 0", hsId)

		initialVersion = rsp.GetItem().Version
	}

	pollFn := func() (*hostsets.HostSet, error) {
		timeout := 5 * time.Second
		ctxwt, cancel := context.WithTimeout(context.Background(), timeout)
		t.Cleanup(cancel)

		for {
			if ctxwt.Err() != nil {
				return nil, fmt.Errorf("pollForSetSyncJobFinish: reached %s timeout when polling for host set version increment", timeout.String())
			}

			rsp, err := hscl.Read(context.Background(), hsId)
			if err == nil && rsp != nil && rsp.GetItem() != nil {
				if rsp.GetItem().Version > initialVersion {
					return rsp.GetItem(), nil
				}
			}

			<-time.After(500 * time.Millisecond)
		}
	}

	return pollFn
}

// getHostCatalogSecrets retrieves the secrets for a given host catalog using
// Boundary's KMS. The host catalog's id and scope id are required. This is used
// in tests to reuse AWS credentials (eg: Obtaining rotated credentials to be
// used in further tests) since access key count is limited to 2.
func getHostCatalogSecrets(t *testing.T, rw *db.Db, k *kms.Kms, hc *hostcatalogs.HostCatalog) *structpb.Struct {
	ctx := context.Background()

	require.NotNil(t, rw, "getHostCatalogSecrets: no database read/writer")
	require.NotNil(t, k, "getHostCatalogSecrets: no kms")
	require.NotNil(t, hc, "getHostCatalogSecrets: no host catalog")
	require.NotEmpty(t, hc.Id, "getHostCatalogSecrets: host catalog id not available")
	require.NotEmpty(t, hc.ScopeId, "getHostCatalogSecrets: host catalog %q scope id not available", hc.Id)

	var secrets *structpb.Struct
	_, _ = rw.DoTx(ctx, 0, db.ConstBackoff{}, func(txr db.Reader, txw db.Writer) error {
		hcs := &plugin.HostCatalogSecret{
			HostCatalogSecret: &store.HostCatalogSecret{
				CatalogId: hc.Id,
			},
		}
		require.NoError(t, txr.LookupById(ctx, hcs), "getHostCatalogSecrets: failed to lookup secrets for host catalog %q", hc.Id)
		require.NotEmpty(t, hcs.HostCatalogSecret.CtSecret, "getHostCatalogSecrets: secrets for host catalog %q lookup successful but no data found in response", hc.Id)

		w, err := k.GetWrapper(ctx, hc.ScopeId, kms.KeyPurposeDatabase)
		require.NoError(t, err, "getHostCatalogSecrets: failed to get kms wrapper")

		require.NoError(t, structwrapping.UnwrapStruct(ctx, w, hcs.HostCatalogSecret, nil), "getHostCatalogSecrets: failed to unwrap secrets")
		hcs.CtSecret = nil

		secrets = new(structpb.Struct)
		require.NoError(t, proto.Unmarshal(hcs.GetSecret(), secrets), "getHostCatalogSecrets: failed to unmarshal secrets into proto struct")
		delete(secrets.GetFields(), "creds_last_rotated_time") // We don't want this to be passed into subsequent host catalog calls.

		return nil
	})
	require.NotNil(t, secrets, "getHostCatalogSecrets: nil secrets after attempting to obtain them")

	return secrets
}

// removeSecretsCredsLastRotatedTime grabs the current secrets for a host
// catalog and sets them back into the database but without
// "creds_last_rotated_time". This is used in these tests to prevent the AWS
// plugin from deleting credentials during host catalog update/delete
// operations.
func removeSecretsCredsLastRotatedTime(t *testing.T, rw *db.Db, k *kms.Kms, hc *hostcatalogs.HostCatalog) {
	ctx := context.Background()

	secrets := getHostCatalogSecrets(t, rw, k, hc)
	delete(secrets.GetFields(), "creds_last_rotated_time")

	require.NotEmpty(t, hc.Id, "removeSecretsCredsLastRotatedTime: no host catalog id available")
	require.NotEmpty(t, hc.ScopeId, "removeSecretsCredsLastRotatedTime: no host catalog %q scope id available", hc.Id)
	require.NotNil(t, secrets, "removeSecretsCredsLastRotatedTime: no host catalog %q secrets available", hc.Id)
	require.NotEmpty(t, secrets.GetFields(), "removeSecretsCredsLastRotatedTime: no secrets found for host catalog %q", hc.Id)

	_, _ = rw.DoTx(ctx, 0, db.ExpBackoff{}, func(txr db.Reader, txw db.Writer) error {
		secretsBytes, err := proto.Marshal(secrets)
		require.NoError(t, err, "removeSecretsCredsLastRotatedTime: failed to marshal secrets proto")
		require.NotEmpty(t, secretsBytes, "removeSecretsCredsLastRotatedTime: empty secrets bytes after marshalling")

		hcs := &plugin.HostCatalogSecret{
			HostCatalogSecret: &store.HostCatalogSecret{
				CatalogId: hc.Id,
				Secret:    secretsBytes,
			},
		}

		w, err := k.GetWrapper(ctx, hc.ScopeId, kms.KeyPurposeDatabase)
		require.NoError(t, err, "removeSecretsCredsLastRotatedTime: failed to get kms wrapper")

		err = structwrapping.WrapStruct(ctx, w, hcs.HostCatalogSecret, nil)
		require.NoError(t, err, "removeSecretsCredsLastRotatedTime: failed to wrap secrets")

		hcs.KeyId, err = w.KeyId(ctx)
		require.NoError(t, err, "removeSecretsCredsLastRotatedTime: failed to get kms key id")
		require.NotEmpty(t, hcs.GetKeyId(), "removeSecretsCredsLastRotatedTime: no kms key id found")

		hcs.Secret = nil

		err = txw.Create(ctx, hcs, db.WithOnConflict(&db.OnConflict{
			Target: db.Columns{"catalog_id"},
			Action: db.SetColumns([]string{"secret", "key_id"}),
		}))
		require.NoError(t, err, "removeSecretsCredsLastRotatedTime: failed to update host catalog %q secrets", hc.Id)

		return nil
	})
}

func randString(n int) string {
	runes := []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = runes[rand.Intn(len(runes))]
	}
	return string(b)
}
