// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

// Test_MigrationStorageBucketCredential: in this test we will create a storage bucket
// that utilizes an encrypted secret stored within the storage_plugin_storage_bucket_secret
// table. Post migration, the entry from the storage_plugin_storage_bucket_secret should
// be moved to the storage_bucket_credential_managed_secret table. This test will also
// validate that storage_plugin_storage_bucket entries that do not have encrypted secrets,
// will create entries in the storage_bucket_credential_environmental table.
func Test_MigrationStorageBucketCredential(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 87001
	currentMigration := 88001

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	want := &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   priorMigration,
				DatabaseSchemaVersion: priorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// Seed the data
	pluginId := "plg________1"
	insertPlugin := "insert into plugin (public_id, scope_id) values ('plg________1', 'global')"
	_, err = d.ExecContext(ctx, insertPlugin)
	require.NoError(err)

	insertPluginSupported := "insert into plugin_storage_supported (public_id) values ('plg________1')"
	_, err = d.ExecContext(ctx, insertPluginSupported)
	require.NoError(err)

	envStorageBucketId := "sb_________1"
	managedSecretStorageBucketId := "sb_________2"
	insertStorageBucket := "insert into storage_plugin_storage_bucket (public_id, scope_id, name, version, plugin_id, bucket_name, worker_filter) values ($1, 'global', $2, 1, $3, 'bucket', 'pki')"
	_, err = d.ExecContext(ctx, insertStorageBucket, envStorageBucketId, "env bucket", pluginId)
	require.NoError(err)
	_, err = d.ExecContext(ctx, insertStorageBucket, managedSecretStorageBucketId, "managed secret bucket", pluginId)
	require.NoError(err)

	insertRootKey := "insert into kms_root_key (scope_id, private_id) values ('global', 'krk_____test')"
	_, err = d.ExecContext(ctx, insertRootKey)
	require.NoError(err)

	insertRootKeyVersion := "insert into kms_root_key_version (root_key_id, private_id, key) values ('krk_____test', 'krkv____test', '_______test'::bytea)"
	_, err = d.ExecContext(ctx, insertRootKeyVersion)
	require.NoError(err)

	insertKmsDataKey := "insert into kms_data_key (root_key_id, private_id, purpose) values ('krk_____test', 'kdk_____test', 'database')"
	_, err = d.ExecContext(ctx, insertKmsDataKey)
	require.NoError(err)

	insertKmsDataKeyVersion := "insert into kms_data_key_version (root_key_version_id, data_key_id, private_id, key) values ('krkv____test', 'kdk_____test', 'kdkv____test', '_______test'::bytea)"
	_, err = d.ExecContext(ctx, insertKmsDataKeyVersion)
	require.NoError(err)

	insertStorageBucketSecret := "insert into storage_plugin_storage_bucket_secret (storage_bucket_id, secrets_encrypted, key_id) values ($1, $2, $3)"
	_, err = d.ExecContext(ctx, insertStorageBucketSecret, managedSecretStorageBucketId, []byte("hello_world"), "kdkv____test")
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
	state, err = m.CurrentState(ctx)
	require.NoError(err)

	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   currentMigration,
				DatabaseSchemaVersion: currentMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// Assert that 'sb_________1' has a storage_bucket_credential_environmental entry
	var count int
	row := d.QueryRowContext(ctx, "select count(*) from storage_bucket_credential_environmental where storage_bucket_id = 'sb_________1'")
	require.NoError(row.Err())
	require.NoError(row.Scan(&count))
	require.Equal(1, count)

	// Assert that 'sb_________2' has a storage_bucket_credential_managed_secret entry
	row = d.QueryRowContext(ctx, "select count(*) from storage_bucket_credential_managed_secret where storage_bucket_id = 'sb_________2'")
	require.NoError(row.Err())
	require.NoError(row.Scan(&count))
	require.Equal(1, count)
}
