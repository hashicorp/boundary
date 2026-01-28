// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
	"github.com/hashicorp/boundary/internal/db/schema/migrations/oss"
	"github.com/hashicorp/boundary/internal/db/schema/migrations/oss/internal/hook46001"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

func TestMigrationHook46001(t *testing.T) {
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

	// The reason why we are starting at 43001 is because one of the security vulnerabilities was a
	// bad trigger on table target_host_set that was suppose to validate scope_id integrity between
	// the target & host set. In migration 44002, this trigger is fixed.
	oss.ApplyMigration(t, ctx, d, 43001)

	// Insert test data into the database.
	populateScopes(t, rw)
	populateKMS(t, rw)

	// Belongs to PRJA___65001
	populateTarget(t, rw)

	// Valid associations to target
	populateStaticCredential(t, rw, "PRJA___65001")
	populateCredentialLibrary(t, rw, "PRJA___65001")
	populateHostSet(t, rw, "PRJA___65001")

	// Illegal associations to target
	populateStaticCredential(t, rw, "PRJB___65001")
	populateCredentialLibrary(t, rw, "PRJB___65001")
	populateHostSet(t, rw, "PRJB___65001")

	// Apply migrations 4400x, 4500x
	migrationIds := []int{44001, 44002, 44003, 44004, 45001, 45002, 45003}
	for _, migrationId := range migrationIds {
		oss.ApplyMigration(t, ctx, d, migrationId)
	}

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Run hook check
	checkReport, err := hook46001.FindIllegalAssociations(ctx, tx)
	require.NoError(t, err)

	// Run hook repair
	repairReport, err := hook46001.RepairIllegalAssociations(ctx, tx)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// Hook validations
	validateCheckFunc(t, checkReport)
	validateRepairFunc(t, rw, repairReport)
}

func populateScopes(t *testing.T, rw *db.Db) {
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
	  ('global', 'org', 'o_test___65001', 'Testing Invalid Target Associations')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into iam_scope
	  (parent_id,         type,      public_id,        name)
	values
	  ('o_test___65001', 'project', 'p_PRJA___65001', 'testing 65001 Project A'),
	  ('o_test___65001', 'project', 'p_PRJB___65001', 'testing 65001 Project B')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)
}

func populateKMS(t *testing.T, rw *db.Db) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()

	var (
		err   error
		query string
	)

	query = `
	insert into kms_root_key
      (private_id,         scope_id)
    values
      ('krk________65001', 'o_test___65001')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into kms_root_key_version
	  (private_id,          root_key_id,        key)
	values
	  ('krkv________65001', 'krk________65001', '________65001'::bytea)`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into kms_data_key
      (private_id,         root_key_id,        purpose)
    values
      ('kdk________65001', 'krk________65001', 'database')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = `
	insert into kms_data_key_version
      (private_id,           data_key_id,       root_key_version_id, key)
    values
      ('kdkv_PRJA___65001', 'kdk________65001', 'krkv________65001', '________65001'::bytea),
	  ('kdkv_PRJB___65001', 'kdk________65001', 'krkv________65001', '________65001'::bytea)`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)
}

func populateTarget(t *testing.T, rw *db.Db) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()

	var (
		err   error
		query string
	)
	query = `
	insert into target_tcp
      (scope_id,         public_id,             name)
    values
      ('p_PRJA___65001', 'ttcp_PRJA___65001', 'Test Target Project A')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)
}

func populateStaticCredential(t *testing.T, rw *db.Db, projectId string) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()

	var (
		err   error
		query string
	)
	query = fmt.Sprintf(`
	insert into credential_static_store
	  (scope_id,   public_id,    name,   description)
	values
	  ('p_%[1]s', 'csst_%[1]s', '%[1]s', 'None')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into credential_static_username_password_credential
	  (store_id,      public_id,     name,                           description, username, password_encrypted,  password_hmac, key_id)
	values
	  ('csst_%[1]s', 'credup_%[1]s', 'test %[1]s static credential', 'None',      'admin', 'encrypted_password', 'hmac-value', 'kdkv_%[1]s')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into target_static_credential
	  (target_id,           credential_static_id,  credential_purpose)
	values
	  ('ttcp_PRJA___65001', 'credup_%s',           'brokered')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)
}

func populateCredentialLibrary(t *testing.T, rw *db.Db, projectId string) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()

	var (
		err   error
		query string
	)
	query = fmt.Sprintf(`
	insert into credential_vault_store
      (scope_id,  public_id,     name,                     description, vault_address,          namespace)
    values
      ('p_%[1]s', 'csvlt_%[1]s', 'test credentail library', 'None',      'https://vault.widget', 'default')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into credential_vault_token
      (store_id,       key_id,       status,   token_hmac,         token,        last_renewal_time, expiration_time)
    values
      ('csvlt_%[1]s', 'kdkv_%[1]s', 'current', '%[1]s-hmac-value', 'token-value', now(),             now() + interval '1 hour')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into credential_vault_library
      (store_id,      public_id,     name,              description, vault_path,        http_method, credential_type)
    values
      ('csvlt_%[1]s', 'clvlt_%[1]s', 'test credential', 'None',      '/secrets/kv/one', 'GET',       'username_password')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into target_credential_library
	  (target_id,           credential_library_id, credential_purpose)
	values
	  ('ttcp_PRJA___65001', 'clvlt_%s',            'brokered')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)
}

func populateHostSet(t *testing.T, rw *db.Db, projectId string) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()

	var (
		err   error
		query string
	)
	query = fmt.Sprintf(`
	insert into static_host_catalog
      (scope_id,  public_id,    name)
    values
      ('p_%[1]s', 'hcst_%[1]s', '%[1]s HostCatalog')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into static_host
      (catalog_id,    public_id,   address)
    values
      ('hcst_%[1]s', 'hst_%[1]s', '%[1]s Host')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into static_host_set
      (catalog_id,    public_id,    name)
    values
      ('hcst_%[1]s', 'hsst_%[1]s', '%[1]s HostSet')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into static_host_set_member
	  ( host_id,     set_id,       catalog_id)
    values
      ('hst_%[1]s', 'hsst_%[1]s', 'hcst_%[1]s')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)

	query = fmt.Sprintf(`
	insert into target_host_set
	  (target_id,           host_set_id)
	values
	  ('ttcp_PRJA___65001', 'hsst_%s')`, projectId)
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(err)
}

func validateCheckFunc(t *testing.T, checkReport migration.Problems) {
	t.Helper()
	require := require.New(t)
	require.ElementsMatch(checkReport, migration.Problems{
		"Target ttcp_PRJA___65001 in project p_PRJA___65001 in org o_test___65001 has an illegal association to credential library clvlt_PRJB___65001 in credential store csvlt_PRJB___65001 in project p_PRJB___65001 in org o_test___65001",
		"Target ttcp_PRJA___65001 in project p_PRJA___65001 in org o_test___65001 has an illegal association to host set hsst_PRJB___65001 in host catalog hcst_PRJB___65001 in project p_PRJB___65001 in org o_test___65001",
		"Target ttcp_PRJA___65001 in project p_PRJA___65001 in org o_test___65001 has an illegal association to static credential credup_PRJB___65001 in credential store csst_PRJB___65001 in project p_PRJB___65001 in org o_test___65001",
	})
}

func validateRepairFunc(t *testing.T, rw *db.Db, repairReport migration.Repairs) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()

	require.ElementsMatch(repairReport, migration.Repairs{
		"Removed illegal association from target ttcp_PRJA___65001 in project p_PRJA___65001 in org o_test___65001 to credential library clvlt_PRJB___65001 in credential store csvlt_PRJB___65001 in project p_PRJB___65001 in org o_test___65001",
		"Removed illegal association from target ttcp_PRJA___65001 in project p_PRJA___65001 in org o_test___65001 to host set hsst_PRJB___65001 in host catalog hcst_PRJB___65001 in project p_PRJB___65001 in org o_test___65001",
		"Removed illegal association from target ttcp_PRJA___65001 in project p_PRJA___65001 in org o_test___65001 to static credential credup_PRJB___65001 in credential store csst_PRJB___65001 in project p_PRJB___65001 in org o_test___65001",
	})

	var (
		err   error
		query string
		rows  *sql.Rows
	)
	type targetAssociation struct {
		targetId   string
		resourceId string
	}
	query = `
	with
	ths (target_id, host_set_id) as (
	select ths.target_id, ths.host_set_id
	  from target_host_set as ths
		where ths.target_id = 'ttcp_PRJA___65001'
	),
	tsc (target_id, credential_static_id) as (
	select tsc.target_id, tsc.credential_static_id
	  from target_static_credential as tsc
	    where tsc.target_id = 'ttcp_PRJA___65001'
	),
	tcl (target_id, credential_library_id) as (
	select tcl.target_id, tcl.credential_library_id
	  from target_credential_library as tcl
	  	where tcl.target_id = 'ttcp_PRJA___65001'
	),
	resources (target_id, resource_id) as (
	select target_id, host_set_id as resource_id
	  from ths
	union
	select target_id, credential_static_id as resource_id
	  from tsc
	union
	select target_id, credential_library_id as resource_id
	  from tcl
	)
	select * from resources;`
	rows, err = rw.Query(ctx, query, nil)
	require.NoError(err)
	associations := []targetAssociation{}
	for rows.Next() {
		var targetId, resourceId string
		if err := rows.Scan(&targetId, &resourceId); err != nil {
			require.NoError(err)
		}
		associations = append(associations, targetAssociation{
			targetId:   targetId,
			resourceId: resourceId,
		})
	}
	require.NoError(rows.Err())
	require.Equal([]targetAssociation{
		{
			targetId:   "ttcp_PRJA___65001",
			resourceId: "clvlt_PRJA___65001",
		},
		{
			targetId:   "ttcp_PRJA___65001",
			resourceId: "hsst_PRJA___65001",
		},
		{
			targetId:   "ttcp_PRJA___65001",
			resourceId: "credup_PRJA___65001",
		},
	}, associations)
}
