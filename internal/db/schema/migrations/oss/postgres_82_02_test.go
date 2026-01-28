// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema/migrations/oss"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationHook8202(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(t, err)
	conn, err := db.Open(ctx, dbType, u)
	require.NoError(t, err)
	rw := db.New(conn)

	oss.ApplyMigration(t, ctx, d, 82001) // TODO: this will need to be updated when the migration has been numbered

	// Insert test data into the database.
	populateMigration82002(t, rw)

	// now apply migration 82/002
	oss.ApplyMigration(t, ctx, d, 82002) // TODO: this will need to be updated when the migration has been numbered

	// session recording sr_________1 should now have target org id o_test__82002
	rows, err := rw.Query(ctx, "select target_org_id from recording_session where public_id = @public_id;", []any{sql.Named("public_id", "sr_________1")})
	require.NoError(t, err)
	count := 0
	var targetOrgId *string
	for rows.Next() {
		require.NoError(t, rows.Scan(&targetOrgId))
		count++
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.NoError(t, rows.Err())
	assert.Equal(t, 1, count)
	assert.Equal(t, "o_test__82002", *targetOrgId)

	// session recording sr_________2 should have null target org id
	rows, err = rw.Query(ctx, "select target_org_id from recording_session where public_id = @public_id;", []any{sql.Named("public_id", "sr_________2")})
	require.NoError(t, err)
	defer rows.Close()
	count = 0
	for rows.Next() {
		require.NoError(t, rows.Scan(&targetOrgId))
		count++
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, 1, count)
	assert.Nil(t, targetOrgId)
}

func populateMigration82002(t *testing.T, rw *db.Db) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()

	var (
		err   error
		query string
	)
	query = `
	insert into iam_scope
	  (parent_id, type,  public_id,       name)
	values
	  ('global', 'org', 'o_test__82002', 'Testing Session Recording Target Org Ids'),
	  ('global', 'org', 'o_test2_82002', 'Second test org for Session Recording Target Org Ids');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into iam_scope
	  (parent_id,         type,      public_id,        name)
	values
	  ('o_test__82002', 'project', 'p_test__82002', 'testing 82002 Project A'),
	  ('o_test2_82002', 'project', 'p_test2_82002', 'testing 82002 Project B');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into plugin
	  (scope_id, public_id,      name)
	values
	  ('global', 'pl__plg___sb', 'Storage Bucket Plugin');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into plugin_storage_supported
	  (public_id)
	values
	  ('pl__plg___sb');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into storage_plugin_storage_bucket
	  (plugin_id,      scope_id,       public_id,      bucket_name,             worker_filter,        secrets_hmac)
	values
	  ('pl__plg___sb', 'global',       'sb____global', 'Global Storage Bucket', 'test worker filter', '\xdeadbeef');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	// yes, I copied many of these from the colors persona, I am not ashamed
	query = `
	insert into iam_user
	  (scope_id,       public_id,      name)
	values
	  ('o_test__82002', 'u______clare', 'Clare'),
	  ('o_test2_82002', 'u______clara', 'Clara');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into kms_root_key
	  (scope_id,       private_id)
	values
	  ('o_test__82002', 'krk___colors'),
	  ('o_test2_82002', 'krk__colors2');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into kms_root_key_version
	  (root_key_id,    private_id,     key)
	values
	  ('krk___colors', 'krkv__colors', '_______color1'::bytea),
	  ('krk__colors2', 'krkv_colors2', '_______color2'::bytea);`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into kms_data_key
	  (root_key_id,    private_id,     purpose)
	values
	  ('krk___colors', 'kdk___colors', 'database'),
	  ('krk__colors2', 'kdk__colors2', 'database');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into kms_data_key_version
	  (root_key_version_id, data_key_id,    private_id,     key)
	values
	  ('krkv__colors',      'kdk___colors', 'kdkv__colors', '_______color3'::bytea),
	  ('krkv_colors2',      'kdk__colors2', 'kdkv_colors2', '_______color4'::bytea);`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into auth_password_conf
	  (password_method_id, private_id)
	values
	  ('apm___colors',     'apmc__colors'),
	  ('apm__colors2',     'apmc_colors2');

	-- Add password auth method to organizations
	insert into auth_password_method
	  (scope_id,         public_id,      password_conf_id, name)
	values
	  ('o_test__82002', 'apm___colors', 'apmc__colors',   'Colors Auth Password'),
	  ('o_test2_82002', 'apm__colors2', 'apmc_colors2',   'Colors 2 Auth Password');

	insert into auth_password_account
	  (auth_method_id, public_id,      login_name)
	values
	  ('apm___colors', 'apa____clare', 'clare'),
	  ('apm__colors2', 'apa____clara', 'clara');

	update auth_account set iam_user_id = 'u______clare' where public_id = 'apa____clare';
	update auth_account set iam_user_id = 'u______clara' where public_id = 'apa____clara';

	insert into auth_token
	  (key_id,         auth_account_id, public_id,      token)
	values
	  ('kdkv__colors', 'apa____clare',  'tok____clare', 'tok____clare'::bytea),
	  ('kdkv_colors2', 'apa____clara',  'tok____clara', 'tok____clara'::bytea);`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	// Add Test Session Recording
	query = `
	insert into target_ssh
	  (project_id,       public_id,           name,              enable_session_recording, storage_bucket_id)
	values
	  ('p_test__82002', 'tssh_test__82002', 'Test SSH Target', true,                     'sb____global'),
	  ('p_test2_82002', 'tssh_test2_82002', 'Test2 SSH Target', true,                    'sb____global');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into session
	  (project_id,       target_id,           public_id,        user_id,        auth_token_id,  certificate,  endpoint)
	values
	  ('p_test__82002', 'tssh_test__82002', 's_test__82002', 'u______clare', 'tok____clare', 'abc'::bytea, 'ep1'),
	  ('p_test2_82002', 'tssh_test2_82002', 's_test2_82002', 'u______clara', 'tok____clara', 'abc'::bytea, 'ep1');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into recording_session
	  (public_id,      storage_bucket_id, session_id)
	values
	  ('sr_________1',    'sb____global', 's_test__82002'),
	  ('sr_________2',    'sb____global', 's_test2_82002');`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	// delete the second org so we can confirm missing orgs are still null after migration
	query = `
	delete from iam_scope where public_id = 'o_test2_82002';`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)
}
