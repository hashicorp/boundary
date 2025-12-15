// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"database/sql"
	"fmt"
	"math/rand/v2"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// TestVaultCredLibRefactor tests the credential_vault_library refactor. It
// inserts state in the changed tables prior to the refactor migration, executes
// the refactor migration and then asserts that this state is still correct.
//
// For structural tests, see
// sqltest/tests/credential/vault/credential_vault_library_refactor.sql.
//
// For context, see 99/README.md.
func TestVaultCredLibRefactor(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	c := testVaultCredLibRefactorDbSetupCounts{
		orgs:                        2,
		projectsPerOrg:              4,
		vaultGenericCredLibs:        20,
		vaultGenericCredLibsDeleted: 5,
		vaultSshCertCredLibs:        20,
		vaultSshCertCredLibsDeleted: 5,
	}

	dataBeforeMigration, dataAfterMigration := testVaultCredLibRefactorDbSetup(t, c)
	require.NotEmpty(dataBeforeMigration)
	require.NotEmpty(dataAfterMigration)

	// Validate that `testVaultCredLibRefactorDbSetup` seeded data correctly
	// according to the count variables above.
	require.Len(dataBeforeMigration.orgs, c.orgs)
	require.Len(dataBeforeMigration.projects, c.orgs*c.projectsPerOrg)
	require.Len(dataBeforeMigration.credentialStores, c.orgs*c.projectsPerOrg)
	require.Len(dataBeforeMigration.credLibBase, (c.orgs*c.projectsPerOrg*c.vaultGenericCredLibs)+(c.orgs*c.projectsPerOrg*c.vaultSshCertCredLibs))
	require.NotEmpty(dataBeforeMigration.credLibHistoryBase) // Some credential libraries have been updated so they'll have more than 1 history entry.
	require.Len(dataBeforeMigration.postRefactorVaultCredLibBase, 0)
	require.Len(dataBeforeMigration.vaultGenericCredLibs, c.orgs*c.projectsPerOrg*c.vaultGenericCredLibs)
	require.Len(dataBeforeMigration.vaultSshCertCredLibs, c.orgs*c.projectsPerOrg*c.vaultSshCertCredLibs)
	require.Len(dataBeforeMigration.deletedVaultGenericCredLibs, c.orgs*c.projectsPerOrg*c.vaultGenericCredLibsDeleted)
	require.Len(dataBeforeMigration.deletedVaultSshCertCredLibs, c.orgs*c.projectsPerOrg*c.vaultSshCertCredLibsDeleted)

	// Validate migrated data. Given that we asserted the data before migration
	// is correctly seeded, we can just assert that post-migration and
	// pre-migration elements match.
	require.ElementsMatch(dataBeforeMigration.orgs, dataAfterMigration.orgs)
	require.ElementsMatch(dataBeforeMigration.projects, dataAfterMigration.projects)
	require.ElementsMatch(dataBeforeMigration.credentialStores, dataAfterMigration.credentialStores)
	require.ElementsMatch(dataBeforeMigration.credLibBase, dataAfterMigration.credLibBase)
	require.ElementsMatch(dataBeforeMigration.credLibHistoryBase, dataAfterMigration.credLibHistoryBase)
	require.ElementsMatch(dataBeforeMigration.credLibBase, dataAfterMigration.postRefactorVaultCredLibBase) // We fill new credential_vault_library with data from credential_library.
	require.ElementsMatch(dataBeforeMigration.vaultGenericCredLibs, dataAfterMigration.vaultGenericCredLibs)
	require.ElementsMatch(dataBeforeMigration.vaultSshCertCredLibs, dataAfterMigration.vaultSshCertCredLibs)
	require.ElementsMatch(dataBeforeMigration.deletedVaultGenericCredLibs, dataAfterMigration.deletedVaultGenericCredLibs)
	require.ElementsMatch(dataBeforeMigration.deletedVaultSshCertCredLibs, dataAfterMigration.deletedVaultSshCertCredLibs)

	// Finally, check table and view row counts.
	require.EqualValues(dataBeforeMigration.rowCounts.credLib, dataAfterMigration.rowCounts.credLib)
	require.EqualValues(dataBeforeMigration.rowCounts.credLibHistory, dataAfterMigration.rowCounts.credLibHistory)
	require.EqualValues(dataBeforeMigration.rowCounts.credLib, dataAfterMigration.rowCounts.credVaultLibPostRefactor) // We fill new credential_vault_library from credential_library.
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibMappingOvrd, dataAfterMigration.rowCounts.credVaultGenericLibMappingOvrd)

	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLib, dataAfterMigration.rowCounts.credVaultGenericLib)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibHistory, dataAfterMigration.rowCounts.credVaultGenericLibHistory)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibDeleted, dataAfterMigration.rowCounts.credVaultGenericLibDeleted)

	require.EqualValues(dataBeforeMigration.rowCounts.credVaultSshCertLib, dataAfterMigration.rowCounts.credVaultSshCertLib)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultSshCertLibHistory, dataAfterMigration.rowCounts.credVaultSshCertLibHistory)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultSshCertLibDeleted, dataAfterMigration.rowCounts.credVaultSshCertLibDeleted)

	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibMappingOvrdUserPass, dataAfterMigration.rowCounts.credVaultGenericLibMappingOvrdUserPass)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibMappingOvrdUserPassDomain, dataAfterMigration.rowCounts.credVaultGenericLibMappingOvrdUserPassDomain)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibMappingOvrdSshPk, dataAfterMigration.rowCounts.credVaultGenericLibMappingOvrdSshPk)

	require.EqualValues(dataBeforeMigration.rowCounts.credVaultLibIssueCredentials, dataAfterMigration.rowCounts.credVaultLibIssueCredentials)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibListLookup, dataAfterMigration.rowCounts.credVaultGenericLibListLookup)
	require.EqualValues(dataBeforeMigration.rowCounts.credVaultGenericLibHistoryAgg, dataAfterMigration.rowCounts.credVaultGenericLibHistoryAgg)
	require.EqualValues(dataBeforeMigration.rowCounts.credDimensionSource, dataAfterMigration.rowCounts.credDimensionSource)
}

// testVaultCredLibRefactorDbSetup sets up a Boundary database running a prior
// migration with credential library data, then migrates to the refactored
// version. Not designed to be called outside of TestVaultCredLibRefactor.
func testVaultCredLibRefactorDbSetup(t testing.TB, counts testVaultCredLibRefactorDbSetupCounts) (beforeMigration, afterMigration dbData) {
	require := require.New(t)

	const priorMigration = 98006
	const credlibRefactorMigration = 99001

	dialect := dbtest.Postgres
	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(err)
	t.Cleanup(func() { require.NoError(c()) })

	db, err := common.SqlOpen(dialect, u)
	require.NoError(err)

	// Migrate to the prior migration (before the one we want to test).
	m, err := schema.NewManager(t.Context(), schema.Dialect(dialect), db, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(t.Context())
	require.NoError(err)

	state, err := m.CurrentState(t.Context())
	require.NoError(err)
	require.Equal(&schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   priorMigration,
				DatabaseSchemaVersion: priorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}, state)

	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{})
	require.NoError(err)
	require.NotNil(tx)

	// Queries to seed all the required data.
	createOrgScopeQuery := `
        insert into iam_scope
            (parent_id, type,  public_id, name)
        values
            ('global',  'org',        $1,   $2);
	`
	createProjectScopeQuery := `
        insert into iam_scope
            (parent_id, type,      public_id, name)
        values
            (       $1, 'project',        $2,   $3);
	`
	createCredStoreQuery := `
        insert into credential_vault_store
            (public_id, project_id, name, vault_address)
        values
            (       $1,         $2,   $3,            $4);
	`
	createVaultGenericCredLibQuery := `
        insert into credential_vault_library
            (public_id, store_id, project_id, name, description, credential_type, vault_path, http_method, http_request_body)
        values
            (       $1,       $2,         $3,   $4,          $5,              $6,         $7,          $8,                $9);
	`
	updateVaultGenericCredLibQuery := `
        update credential_vault_library
           set name        = $1,
               description = $2,
               vault_path  = $3
         where public_id = $4;
	`
	deleteVaultGenericCredLibQuery := `
        delete from credential_vault_library
              where public_id = $1;
	`
	createUpMappingOvrdQuery := `
        insert into credential_vault_library_username_password_mapping_override
            (library_id, username_attribute, password_attribute)
        values
            (        $1,                 $2,                 $3);
	`
	createUpdMappingOvrdQuery := `
        insert into credential_vault_library_username_password_domain_mapping_ovrd
            (library_id, username_attribute, password_attribute, domain_attribute)
        values
            (        $1,                 $2,                 $3,               $4);
	`
	createSshPkMappingOvrdQuery := `
        insert into credential_vault_library_ssh_private_key_mapping_override
            (library_id, username_attribute, private_key_attribute, private_key_passphrase_attribute)
        values
            (        $1,                 $2,                    $3,                               $4);
	`
	createVaultSshCertCredLibQuery := `
        insert into credential_vault_ssh_cert_library
            (public_id, store_id, project_id, name, description,   credential_type, vault_path, username, key_type, key_bits, ttl, key_id, critical_options, extensions, additional_valid_principals)
        values
            (       $1,       $2,         $3,   $4,          $5, 'ssh_certificate',         $6,       $7,       $8,       $9, $10,    $11,              $12,        $13,                         $14);
	`
	updateVaultSshCertCredLibQuery := `
        update credential_vault_ssh_cert_library
           set name        = $1,
               description = $2,
               vault_path  = $3,
               username    = $4
         where public_id = $5;
	`
	deleteVaultSshCertCredLibQuery := `
        delete from credential_vault_ssh_cert_library
              where public_id = $1;
	`

	execOk := func(res sql.Result, err error) {
		// Exec returned no error.
		require.NoError(err)
		require.NotNil(res)

		// Exec affected at least 1 row.
		ra, err := res.RowsAffected()
		require.NoError(err)
		require.Greater(ra, int64(0))
	}

	// Create org scopes.
	for range counts.orgs {
		orgId := fmt.Sprintf("o_%s", base62.MustRandom(10))
		orgName := fmt.Sprintf("Test %q Org Scope", orgId)
		execOk(tx.ExecContext(t.Context(), createOrgScopeQuery, orgId, orgName))

		// For each org scope, create `projectsPerOrgCount` project scopes and a
		// Vault credential store.
		for range counts.projectsPerOrg {
			projectId := fmt.Sprintf("p_%s", base62.MustRandom(10))
			projectName := fmt.Sprintf("Test %q Project Scope", projectId)
			execOk(tx.ExecContext(t.Context(), createProjectScopeQuery, orgId, projectId, projectName))

			credStoreId := fmt.Sprintf("csst_%s", base62.MustRandom(10))
			credStoreName := fmt.Sprintf("Test %q Vault Credential Store", credStoreId)
			execOk(tx.ExecContext(t.Context(), createCredStoreQuery, credStoreId, projectId, credStoreName, "http://127.0.0.1:8200"))

			// For each credential store, create `vaultGenericCredLibs` Vault
			// generic credential libraries with differing configurations and
			// mapping overrides. Add `vaultGenericCredLibsDeleted` to account
			// for the ones we have to create to delete.
			deletedVaultGenericCredLibs := 0
			for range counts.vaultGenericCredLibs + counts.vaultGenericCredLibsDeleted {
				vgCredLibId := fmt.Sprintf("clvlt_%s", base62.MustRandom(10))
				vgCredLibName := fmt.Sprintf("Test %q Vault Generic Credential Library", base62.MustRandom(10))

				var vgCredType string
				switch rand.IntN(4) {
				case 0:
					vgCredType = "unspecified"
				case 1:
					vgCredType = "username_password"
				case 2:
					vgCredType = "username_password_domain"
				case 3:
					vgCredType = "ssh_private_key"
				}

				var vgHttpMethod string
				var vgHttpReqBody []byte
				switch rand.IntN(2) {
				case 0:
					vgHttpMethod = "GET"
				case 1:
					vgHttpMethod = "POST"
					vgHttpReqBody = []byte(`{"my_custom_request_body":true, "data": "this_is_some_data"}`)
				}

				execOk(tx.ExecContext(t.Context(), createVaultGenericCredLibQuery,
					vgCredLibId, credStoreId, projectId, vgCredLibName, vgCredLibName,
					vgCredType, "/my/vg/vault/path", vgHttpMethod, vgHttpReqBody,
				))

				var vgMappingOverrideQuery string
				vgMappingOverrideArgs := []any{vgCredLibId}
				switch vgCredType {
				case "unspecified": // No mapping override.
				case "username_password":
					vgMappingOverrideQuery = createUpMappingOvrdQuery
					vgMappingOverrideArgs = append(vgMappingOverrideArgs, "username_ovrd", "password_ovrd")
				case "username_password_domain":
					vgMappingOverrideQuery = createUpdMappingOvrdQuery
					vgMappingOverrideArgs = append(vgMappingOverrideArgs, "username_ovrd", "password_ovrd", "domain_ovrd")
				case "ssh_private_key":
					vgMappingOverrideQuery = createSshPkMappingOvrdQuery
					vgMappingOverrideArgs = append(vgMappingOverrideArgs, "username_ovrd", "ssh_pk_ovrd", "ssh_pk_passphrase_ovrd")
				}
				if vgMappingOverrideQuery != "" {
					execOk(tx.ExecContext(t.Context(), vgMappingOverrideQuery, vgMappingOverrideArgs...))
				}

				// Chance of updating the credential library.
				switch rand.IntN(10) {
				case 0:
					execOk(tx.ExecContext(t.Context(), updateVaultGenericCredLibQuery, "Updated"+vgCredLibName,
						"Updated"+vgCredLibName, "/my/updated/vault/path", vgCredLibId))
				}

				if counts.vaultGenericCredLibsDeleted > deletedVaultGenericCredLibs {
					execOk(tx.ExecContext(t.Context(), deleteVaultGenericCredLibQuery, vgCredLibId))
					deletedVaultGenericCredLibs++
				}
			}

			// For each credential store, create `vaultSshCertCredLibs` Vault
			// SSH Certificate credential libraries with different
			// configurations. Add `vaultSshCertCredLibsDeleted` to account for
			// the ones we have to create to delete.
			deletedSshCertCredLibs := 0
			for range counts.vaultSshCertCredLibs + counts.vaultSshCertCredLibsDeleted {
				vSshCertCredLibId := fmt.Sprintf("clvsclt_%s", base62.MustRandom(10))
				vSshCertCredLibName := fmt.Sprintf("Test %q Vault SSH Certificate Credential Library", base62.MustRandom(10))

				var keyType string
				var keyBits int
				switch rand.IntN(3) {
				case 0:
					keyType = "ed25519"
					keyBits = 0
				case 1:
					keyType = "ecdsa"
					keyBits = 521
				case 2:
					keyType = "rsa"
					keyBits = 4096
				}

				var ttl string
				switch rand.IntN(2) {
				case 0: // No TTL.
				case 1:
					ttl = strconv.FormatInt(rand.Int64N(65536), 10)
				}

				var keyId string
				switch rand.IntN(2) {
				case 0: // No key id.
				case 1:
					keyId = "my_key_id"
				}

				var criticalOptions []byte
				switch rand.IntN(2) {
				case 0: // No Critical options.
				case 1:
					criticalOptions = []byte(`critical_option1=yes, critical_option2=alsoyes, critical_option3=yep`)
				}

				var extensions []byte
				switch rand.IntN(2) {
				case 0: // No extensions.
				case 1:
					extensions = []byte(`extension1=yes, extension2=alsoyes, extension3=yep`)
				}

				var additionalPrincipals string
				switch rand.IntN(2) {
				case 0: // No additional principals.
				case 1:
					additionalPrincipals = "principal1, principal2, principal3"
				}

				execOk(tx.ExecContext(t.Context(), createVaultSshCertCredLibQuery,
					vSshCertCredLibId, credStoreId, projectId, vSshCertCredLibName,
					vSshCertCredLibName, "/ssh/sign/cert1", "username", keyType,
					keyBits, ttl, keyId, criticalOptions, extensions, additionalPrincipals,
				))
				require.NoError(err)

				// Chance of updating credential library.
				switch rand.IntN(10) {
				case 0:
					execOk(tx.ExecContext(t.Context(), updateVaultSshCertCredLibQuery, "Updated"+vSshCertCredLibName,
						"Updated"+vSshCertCredLibName, "/ssh/issue/updated_cert1", "updated_username", vSshCertCredLibId))
				}

				if counts.vaultSshCertCredLibsDeleted > deletedSshCertCredLibs {
					execOk(tx.ExecContext(t.Context(), deleteVaultSshCertCredLibQuery, vSshCertCredLibId))
					deletedSshCertCredLibs++
				}
			}
		}
	}
	err = tx.Commit()
	require.NoError(err)

	// Get a snapshot of what the data looks like before the migration.
	beforeMigration = testBuildTestVaultCredLibRefactorDbData(t, db, false)

	// Now we're ready for the migration we want to test.
	m, err = schema.NewManager(t.Context(), schema.Dialect(dialect), db, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": credlibRefactorMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(t.Context())
	require.NoError(err)

	state, err = m.CurrentState(t.Context())
	require.NoError(err)
	require.Equal(&schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   credlibRefactorMigration,
				DatabaseSchemaVersion: credlibRefactorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}, state)

	// Get a snapshot of the data after the migration.
	afterMigration = testBuildTestVaultCredLibRefactorDbData(t, db, true)

	return beforeMigration, afterMigration
}

// testBuildTestVaultCredLibRefactorDbData will build a 'dbData' object from
// database queries. Accepts a boolean that denotes if any given call is
// post-refactor. 'false' means assume before refactor migration; 'true' means
// assume after refactor migration. This boolean controls table names on various
// queries that retrieve data.
func testBuildTestVaultCredLibRefactorDbData(t testing.TB, db *sql.DB, afterRefactor bool) dbData {
	require := require.New(t)

	queryContext := func(tx *sql.Tx, query string, callbackFn func(scanFn func(dest ...any) error)) {
		rows, err := tx.QueryContext(t.Context(), query)
		require.NoError(err)
		require.NotNil(rows)

		for rows.Next() {
			callbackFn(rows.Scan)
		}
		require.NoError(rows.Err())
	}

	data := dbData{
		orgs:                         make([]orgProj, 0),
		projects:                     make([]orgProj, 0),
		credentialStores:             make([]vaultCredStore, 0),
		credLibBase:                  make([]credLibBase, 0),
		credLibHistoryBase:           make([]credLibHistoryBase, 0),
		postRefactorVaultCredLibBase: make([]credLibBase, 0),
		vaultGenericCredLibs:         make([]vaultGenericCredLib, 0),
		vaultSshCertCredLibs:         make([]vaultSshCertCredLib, 0),
		deletedVaultGenericCredLibs:  make([]credLibDeleted, 0),
		deletedVaultSshCertCredLibs:  make([]credLibDeleted, 0),
		rowCounts:                    rowCounts{},
	}

	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{})
	require.NoError(err)
	require.NotNil(tx)
	defer func() { _ = tx.Rollback() }()

	// Get org and project scopes.
	queryContext(tx, "select * from iam_scope", func(scanFn func(dest ...any) error) {
		var publicId, name, typ, description, parentId, primaryAuthMethodId *string
		var createTime, updateTime *time.Time
		var version *int
		require.NoError(scanFn(&publicId, &createTime, &updateTime, &name,
			&typ, &description, &parentId, &version, &primaryAuthMethodId),
		)

		op := orgProj{
			publicId:    testDeref(t, publicId),
			name:        testDeref(t, name),
			description: testDeref(t, description),
			createTime:  testDeref(t, createTime),
			updateTime:  testDeref(t, updateTime),
			typ:         testDeref(t, typ),
			parentId:    testDeref(t, parentId),
			version:     testDeref(t, version),
		}
		switch op.typ {
		case "global":
		case "org":
			data.orgs = append(data.orgs, op)
		case "project":
			data.projects = append(data.projects, op)
		default:
			require.Failf("failed to get org/project scopes", "unknown scope type %s", op.typ)
		}
	})

	// Get credential stores.
	queryContext(tx, "select * from credential_vault_store", func(scanFn func(dest ...any) error) {
		var publicId, projectId, name, description, vaultAddr, namespace,
			tlsServerName, workerFilter *string
		var createTime, updateTime, deleteTime *time.Time
		var version *int
		var caCert *[]byte
		var tlsSkipVerify *bool

		require.NoError(scanFn(&publicId, &projectId, &name, &description,
			&createTime, &updateTime, &deleteTime, &version, &vaultAddr, &namespace,
			&caCert, &tlsServerName, &tlsSkipVerify, &workerFilter),
		)

		data.credentialStores = append(data.credentialStores, vaultCredStore{
			publicId:      testDeref(t, publicId),
			projectId:     testDeref(t, projectId),
			name:          testDeref(t, name),
			description:   testDeref(t, description),
			createTime:    testDeref(t, createTime),
			updateTime:    testDeref(t, updateTime),
			deleteTime:    testDeref(t, deleteTime),
			version:       testDeref(t, version),
			vaultAddr:     testDeref(t, vaultAddr),
			namespace:     testDeref(t, namespace),
			caCert:        testDeref(t, caCert),
			tlsServerName: testDeref(t, tlsServerName),
			tlsSkipVerify: testDeref(t, tlsSkipVerify),
			workerFilter:  testDeref(t, workerFilter),
		})
	})

	// Get credential library base table.
	queryContext(tx, "select * from credential_library", func(scanFn func(dest ...any) error) {
		var publicId, storeId, credType, projectId *string
		var createTime, updateTime *time.Time
		require.NoError(scanFn(&publicId, &storeId, &credType, &projectId, &createTime, &updateTime))

		data.credLibBase = append(data.credLibBase, credLibBase{
			publicId:   testDeref(t, publicId),
			storeId:    testDeref(t, storeId),
			credType:   testDeref(t, credType),
			projectId:  testDeref(t, projectId),
			createTime: testDeref(t, createTime),
			updateTime: testDeref(t, updateTime),
		})
	})

	// Get credential library base table if we're post-refactor.
	if afterRefactor {
		queryContext(tx, "select * from credential_vault_library", func(scanFn func(dest ...any) error) {
			var publicId, storeId, credType, projectId *string
			var createTime, updateTime *time.Time
			require.NoError(scanFn(&publicId, &storeId, &credType, &projectId, &createTime, &updateTime))

			data.postRefactorVaultCredLibBase = append(data.postRefactorVaultCredLibBase, credLibBase{
				publicId:   testDeref(t, publicId),
				storeId:    testDeref(t, storeId),
				credType:   testDeref(t, credType),
				projectId:  testDeref(t, projectId),
				createTime: testDeref(t, createTime),
				updateTime: testDeref(t, updateTime),
			})
		})
	}

	// Get credential library history base table.
	queryContext(tx, "select * from credential_library_history_base", func(scanFn func(dest ...any) error) {
		var historyId *string
		require.NoError(scanFn(&historyId))
		data.credLibHistoryBase = append(data.credLibHistoryBase, credLibHistoryBase{testDeref(t, historyId)})
	})

	// Get Vault generic credential libraries.
	vaultGenericCredLibTableName := "credential_vault_library"
	if afterRefactor {
		vaultGenericCredLibTableName = "credential_vault_generic_library"
	}
	queryContext(tx, fmt.Sprintf("select * from %s", vaultGenericCredLibTableName), func(scanFn func(dest ...any) error) {
		var publicId, storeId, name, description, vaultPath, httpMethod,
			credType, projectId *string
		var createTime, updateTime *time.Time
		var version *int
		var httpReqBody *[]byte

		require.NoError(scanFn(&publicId, &storeId, &name, &description,
			&createTime, &updateTime, &version, &vaultPath, &httpMethod,
			&httpReqBody, &credType, &projectId),
		)

		data.vaultGenericCredLibs = append(data.vaultGenericCredLibs, vaultGenericCredLib{
			publicId:    testDeref(t, publicId),
			storeId:     testDeref(t, storeId),
			name:        testDeref(t, name),
			description: testDeref(t, description),
			createTime:  testDeref(t, createTime),
			updateTime:  testDeref(t, updateTime),
			version:     testDeref(t, version),
			vaultPath:   testDeref(t, vaultPath),
			httpMethod:  testDeref(t, httpMethod),
			httpReqBody: testDeref(t, httpReqBody),
			credType:    testDeref(t, credType),
			projectId:   testDeref(t, projectId),

			mappingOverride: vaultGenericCredLibMappingOvrd{},      // Fetch below.
			history:         make([]vaultGenericCredLibHistory, 0), // Fetch below.
		})
	})

	// Get mapping overrides for Vault generic credential libraries.
	upMappingOvrdTableName := "credential_vault_library_username_password_mapping_override"
	updMappingOvrdTableName := "credential_vault_library_username_password_domain_mapping_ovrd"
	sshPkMappingOvrdTableName := "credential_vault_library_ssh_private_key_mapping_override"
	if afterRefactor {
		upMappingOvrdTableName = "credential_vault_generic_library_username_password_mapping_ovrd"
		updMappingOvrdTableName = "credential_vault_generic_library_usern_pass_domain_mapping_ovrd"
		sshPkMappingOvrdTableName = "credential_vault_generic_library_ssh_private_key_mapping_ovrd"
	}
	for _, cl := range data.vaultGenericCredLibs {
		queryFmt := "select * from %s where library_id = '%s'"
		getMappingOvrd := false
		switch cl.credType {
		case "unspecified":
		case "username_password":
			queryFmt = fmt.Sprintf(queryFmt, upMappingOvrdTableName, cl.publicId)
			getMappingOvrd = true
		case "username_password_domain":
			queryFmt = fmt.Sprintf(queryFmt, updMappingOvrdTableName, cl.publicId)
			getMappingOvrd = true
		case "ssh_private_key":
			queryFmt = fmt.Sprintf(queryFmt, sshPkMappingOvrdTableName, cl.publicId)
			getMappingOvrd = true
		default:
			require.Failf("failed to get vault generic mapping overrides", "unknown credential type %s", cl.credType)
		}
		if getMappingOvrd {
			queryContext(tx, queryFmt, func(scanFn func(dest ...any) error) {
				var libraryId, usernameAttr, passwordAttr, domainAttr, pkAttr,
					pkPassphraseAttr *string

				switch cl.credType {
				case "username_password":
					require.NoError(scanFn(&libraryId, &usernameAttr, &passwordAttr))
				case "username_password_domain":
					require.NoError(scanFn(&libraryId, &usernameAttr, &passwordAttr, &domainAttr))
				case "ssh_private_key":
					require.NoError(scanFn(&libraryId, &usernameAttr, &pkAttr, &pkPassphraseAttr))
				}

				cl.mappingOverride = vaultGenericCredLibMappingOvrd{
					libraryId:        testDeref(t, libraryId),
					usernameAttr:     testDeref(t, usernameAttr),
					passwordAttr:     testDeref(t, passwordAttr),
					domainAttr:       testDeref(t, domainAttr),
					pkAttr:           testDeref(t, pkAttr),
					pkPassphraseAttr: testDeref(t, pkPassphraseAttr),
				}
			})
		}
	}

	// Get history for Vault generic credential libraries.
	for _, cl := range data.vaultGenericCredLibs {
		hstTableName := "credential_vault_library_hst"
		if afterRefactor {
			hstTableName = "credential_vault_generic_library_hst"
		}

		query := fmt.Sprintf("select * from %s where public_id = '%s'", hstTableName, cl.publicId)
		queryContext(tx, query, func(scanFn func(dest ...any) error) {
			var publicId, name, description, projectId, storeId, vaultPath,
				httpMethod, credType, historyId, validRange *string
			var httpReqBody *[]byte

			require.NoError(scanFn(&publicId, &name, &description, &projectId,
				&storeId, &vaultPath, &httpMethod, &httpReqBody, &credType,
				&historyId, &validRange),
			)

			cl.history = append(cl.history, vaultGenericCredLibHistory{
				historyId:  testDeref(t, historyId),
				validRange: testDeref(t, validRange),
				cl: vaultGenericCredLib{
					publicId:    testDeref(t, publicId),
					name:        testDeref(t, name),
					description: testDeref(t, description),
					projectId:   testDeref(t, projectId),
					storeId:     testDeref(t, storeId),
					vaultPath:   testDeref(t, vaultPath),
					httpMethod:  testDeref(t, httpMethod),
					httpReqBody: testDeref(t, httpReqBody),
					credType:    testDeref(t, credType),
				},
			})
		})
	}

	// Get Vault SSH certificate credential libraries.
	queryContext(tx, "select * from credential_vault_ssh_cert_library", func(scanFn func(dest ...any) error) {
		var publicId, storeId, name, description, vaultPath, username, keyType,
			ttl, keyId, credType, projectId, additionalPrincipals *string
		var createTime, updateTime *time.Time
		var version, keyBits *int
		var criticalOptions, extensions *[]byte

		require.NoError(scanFn(&publicId, &storeId, &name, &description,
			&createTime, &updateTime, &version, &vaultPath, &username, &keyType,
			&keyBits, &ttl, &keyId, &criticalOptions, &extensions, &credType,
			&projectId, &additionalPrincipals),
		)

		data.vaultSshCertCredLibs = append(data.vaultSshCertCredLibs, vaultSshCertCredLib{
			publicId:                  testDeref(t, publicId),
			storeId:                   testDeref(t, storeId),
			name:                      testDeref(t, name),
			description:               testDeref(t, description),
			createTime:                testDeref(t, createTime),
			updateTime:                testDeref(t, updateTime),
			version:                   testDeref(t, version),
			vaultPath:                 testDeref(t, vaultPath),
			username:                  testDeref(t, username),
			keyType:                   testDeref(t, keyType),
			keyBits:                   testDeref(t, keyBits),
			ttl:                       testDeref(t, ttl),
			keyId:                     testDeref(t, keyId),
			criticalOptions:           testDeref(t, criticalOptions),
			extensions:                testDeref(t, extensions),
			credType:                  testDeref(t, credType),
			projectId:                 testDeref(t, projectId),
			additionalValidPrincipals: testDeref(t, additionalPrincipals),

			history: make([]vaultSshCertCredLibHistory, 0), // Fetch below.
		})
	})

	// Get history for Vault SSH certificate credential libraries.
	for _, cl := range data.vaultSshCertCredLibs {
		query := fmt.Sprintf("select * from credential_vault_ssh_cert_library_hst where public_id = '%s'", cl.publicId)
		queryContext(tx, query, func(scanFn func(dest ...any) error) {
			var publicId, storeId, name, description, vaultPath, username, keyType,
				ttl, credType, projectId, historyId, validRange *string
			var keyBits *int
			var criticalOptions, extensions *[]byte

			require.NoError(scanFn(&publicId, &name, &description, &projectId,
				&storeId, &vaultPath, &username, &keyType, &keyBits, &ttl,
				&criticalOptions, &extensions, &credType, &historyId, &validRange),
			)

			cl.history = append(cl.history, vaultSshCertCredLibHistory{
				historyId:  *historyId,
				validRange: *validRange,
				cl: vaultSshCertCredLib{
					publicId:        testDeref(t, publicId),
					name:            testDeref(t, name),
					description:     testDeref(t, description),
					projectId:       testDeref(t, projectId),
					storeId:         testDeref(t, storeId),
					vaultPath:       testDeref(t, vaultPath),
					username:        testDeref(t, username),
					keyType:         testDeref(t, keyType),
					keyBits:         testDeref(t, keyBits),
					ttl:             testDeref(t, ttl),
					criticalOptions: testDeref(t, criticalOptions),
					extensions:      testDeref(t, extensions),
					credType:        testDeref(t, credType),
				},
			})
		})
	}

	// Get all deleted vault credential libraries.
	vaultGenericCredLibDeletedTableName := "credential_vault_library_deleted"
	if afterRefactor {
		vaultGenericCredLibDeletedTableName = "credential_vault_generic_library_deleted"
	}
	vaultSshCertCredLibDeletedTableName := "credential_vault_ssh_cert_library_deleted"
	deletedTables := []string{vaultGenericCredLibDeletedTableName, vaultSshCertCredLibDeletedTableName}
	for _, dt := range deletedTables {
		queryContext(tx, fmt.Sprintf("select * from %s", dt), func(scanFn func(dest ...any) error) {
			var publicId *string
			var deleteTime *time.Time

			require.NoError(scanFn(&publicId, &deleteTime))

			cld := credLibDeleted{
				publicId:   testDeref(t, publicId),
				deleteTime: testDeref(t, deleteTime),
			}
			switch dt {
			case vaultGenericCredLibDeletedTableName:
				data.deletedVaultGenericCredLibs = append(data.deletedVaultGenericCredLibs, cld)
			case vaultSshCertCredLibDeletedTableName:
				data.deletedVaultSshCertCredLibs = append(data.deletedVaultSshCertCredLibs, cld)
			}
		})
	}

	// Get row counts.
	var rowCountQuery string
	if !afterRefactor {
		rowCountQuery = `
            select
                ( select count(*) from credential_library ),
                ( select count(*) from credential_library_history_base ),
                ( select count(*) from credential_vault_library_mapping_override ),

                ( select count(*) from credential_vault_library ),
                ( select count(*) from credential_vault_library_hst ),
                ( select count(*) from credential_vault_library_deleted ),

                ( select count(*) from credential_vault_ssh_cert_library ),
                ( select count(*) from credential_vault_ssh_cert_library_hst ),
                ( select count(*) from credential_vault_ssh_cert_library_deleted ),

                ( select count(*) from credential_vault_library_username_password_mapping_override ),
                ( select count(*) from credential_vault_library_username_password_domain_mapping_ovrd ),
                ( select count(*) from credential_vault_library_ssh_private_key_mapping_override ),

                ( select count(*) from credential_vault_library_issue_credentials ),
                ( select count(*) from credential_vault_library_list_lookup ),
                ( select count(*) from credential_vault_library_hst_aggregate ),
                ( select count(*) from whx_credential_dimension_source );
		`
	} else {
		rowCountQuery = `
            select
                ( select count(*) from credential_library ),
                ( select count(*) from credential_library_history_base ),
                ( select count(*) from credential_vault_generic_library_mapping_override ),
                ( select count(*) from credential_vault_library ),

                ( select count(*) from credential_vault_generic_library ),
                ( select count(*) from credential_vault_generic_library_hst ),
                ( select count(*) from credential_vault_generic_library_deleted ),

                ( select count(*) from credential_vault_ssh_cert_library ),
                ( select count(*) from credential_vault_ssh_cert_library_hst ),
                ( select count(*) from credential_vault_ssh_cert_library_deleted ),

                ( select count(*) from credential_vault_generic_library_username_password_mapping_ovrd ),
                ( select count(*) from credential_vault_generic_library_usern_pass_domain_mapping_ovrd ),
                ( select count(*) from credential_vault_generic_library_ssh_private_key_mapping_ovrd ),

                ( select count(*) from credential_vault_library_issue_credentials ),
                ( select count(*) from credential_vault_generic_library_list_lookup ),
                ( select count(*) from credential_vault_generic_library_hst_aggregate ),
                ( select count(*) from whx_credential_dimension_source );
	`
	}
	queryContext(tx, rowCountQuery, func(scanFn func(dest ...any) error) {
		var cl, clHistBase, clVaultBasePostRefactorOnly, clVaultGenericMappingOvrd,
			clVaultGeneric, clVaultGenericHist, clVaultGenericDel, clVaultSshCert,
			clVaultSshCertHist, clVaultSshCertDel, clVaultGenericUpMappingOvrd,
			clVaultGenericUpdMappingOvrd, clVaultGenericSshPkMappingOverd,
			clVaultLibIssueCreds, clVaultGenericListLookup, clVaultGenericHistAgg, credDimensionSource *int64

		if !afterRefactor {
			require.NoError(scanFn(&cl, &clHistBase, &clVaultGenericMappingOvrd,
				&clVaultGeneric, &clVaultGenericHist, &clVaultGenericDel,
				&clVaultSshCert, &clVaultSshCertHist, &clVaultSshCertDel,
				&clVaultGenericUpMappingOvrd, &clVaultGenericUpdMappingOvrd, &clVaultGenericSshPkMappingOverd,
				&clVaultLibIssueCreds, &clVaultGenericListLookup, &clVaultGenericHistAgg, &credDimensionSource),
			)
		} else {
			require.NoError(scanFn(&cl, &clHistBase, &clVaultGenericMappingOvrd, &clVaultBasePostRefactorOnly,
				&clVaultGeneric, &clVaultGenericHist, &clVaultGenericDel,
				&clVaultSshCert, &clVaultSshCertHist, &clVaultSshCertDel,
				&clVaultGenericUpMappingOvrd, &clVaultGenericUpdMappingOvrd, &clVaultGenericSshPkMappingOverd,
				&clVaultLibIssueCreds, &clVaultGenericListLookup, &clVaultGenericHistAgg, &credDimensionSource),
			)
		}

		data.rowCounts = rowCounts{
			credLib:                                      testDeref(t, cl),
			credLibHistory:                               testDeref(t, clHistBase),
			credVaultLibPostRefactor:                     testDeref(t, clVaultBasePostRefactorOnly),
			credVaultGenericLibMappingOvrd:               testDeref(t, clVaultGenericMappingOvrd),
			credVaultGenericLib:                          testDeref(t, clVaultGeneric),
			credVaultGenericLibHistory:                   testDeref(t, clVaultGenericHist),
			credVaultGenericLibDeleted:                   testDeref(t, clVaultGenericDel),
			credVaultSshCertLib:                          testDeref(t, clVaultSshCert),
			credVaultSshCertLibHistory:                   testDeref(t, clVaultSshCertHist),
			credVaultSshCertLibDeleted:                   testDeref(t, clVaultSshCertDel),
			credVaultGenericLibMappingOvrdUserPass:       testDeref(t, clVaultGenericUpMappingOvrd),
			credVaultGenericLibMappingOvrdUserPassDomain: testDeref(t, clVaultGenericUpdMappingOvrd),
			credVaultGenericLibMappingOvrdSshPk:          testDeref(t, clVaultGenericSshPkMappingOverd),
			credVaultLibIssueCredentials:                 testDeref(t, clVaultLibIssueCreds),
			credVaultGenericLibListLookup:                testDeref(t, clVaultGenericListLookup),
			credVaultGenericLibHistoryAgg:                testDeref(t, clVaultGenericHistAgg),
			credDimensionSource:                          testDeref(t, credDimensionSource),
		}
	})

	return data
}

// testDeref is a generic function that dereferences a pointer type,
// safeguarding against a nil pointer dereference. If the input pointer is nil,
// it returns the zero-value for the input type.
func testDeref[T any](_ testing.TB, in *T) T {
	if in == nil {
		return *new(T)
	}
	return *in
}

// dbData is the aggregation of all the data that
// testBuildTestVaultCredLibRefactorDbData gets together. Not designed to be
// used outside of TestVaultCredLibRefactor.
type dbData struct {
	orgs     []orgProj // From iam_scope.
	projects []orgProj // From iam_scope.

	credentialStores []vaultCredStore // From credential_vault_store.

	credLibBase                  []credLibBase        // From credential_library.
	credLibHistoryBase           []credLibHistoryBase // From credential_library_history_base.
	postRefactorVaultCredLibBase []credLibBase        // From credential_vault_library (after refactor only).

	vaultGenericCredLibs []vaultGenericCredLib // From credential_vault_library (pre-refactor) or credential_vault_generic_library.
	vaultSshCertCredLibs []vaultSshCertCredLib // From credential_vault_ssh_cert_library.

	deletedVaultGenericCredLibs []credLibDeleted // From credential_vault_library_deleted (pre-refactor) or credential_vault_generic_library_deleted.
	deletedVaultSshCertCredLibs []credLibDeleted // From credential_vault_ssh_cert_library_deleted.

	rowCounts rowCounts
}

// orgProj holds database data about a org/project scope. Not designed to be
// used outside of testBuildTestVaultCredLibRefactorDbData.
type orgProj struct {
	publicId    string
	name        string
	description string
	createTime  time.Time
	updateTime  time.Time
	typ         string
	parentId    string
	version     int
}

// credLibBase holds database data about a credential library.
// Not designed to be used outside of testBuildTestVaultCredLibRefactorDbData.
type credLibBase struct {
	publicId   string
	storeId    string
	credType   string
	projectId  string
	createTime time.Time
	updateTime time.Time
}

// credLibHistoryBase holds historical data about a credential library. Not
// designed to be used outside of testBuildTestVaultCredLibRefactorDbData.
type credLibHistoryBase struct {
	historyId string
}

// credLibDeleted holds database data about a deleted credential library. Not
// designed to be used outside of testBuildTestVaultCredLibRefactorDbData.
type credLibDeleted struct {
	publicId   string
	deleteTime time.Time
}

// vaultCredStore holds database data about a Vault credential store. Not
// designed to be used outside of testBuildTestVaultCredLibRefactorDbData.
type vaultCredStore struct {
	publicId      string
	projectId     string
	name          string
	description   string
	createTime    time.Time
	updateTime    time.Time
	deleteTime    time.Time
	version       int
	vaultAddr     string
	namespace     string
	caCert        []byte
	tlsServerName string
	tlsSkipVerify bool
	workerFilter  string
}

// vaultGenericCredLib holds database data about a Vault generic credential
// library. Not designed to be used outside of
// testBuildTestVaultCredLibRefactorDbData.
type vaultGenericCredLib struct {
	publicId    string
	storeId     string
	name        string
	description string
	createTime  time.Time
	updateTime  time.Time
	version     int
	vaultPath   string
	httpMethod  string
	httpReqBody []byte
	credType    string
	projectId   string

	mappingOverride vaultGenericCredLibMappingOvrd
	history         []vaultGenericCredLibHistory
}
type vaultGenericCredLibHistory struct {
	cl         vaultGenericCredLib
	historyId  string
	validRange string
}

// vaultSshCertCredLib holds database data about a Vault SSH certificate
// credential library. Not designed to be used outside of
// testBuildTestVaultCredLibRefactorDbData.
type vaultSshCertCredLib struct {
	publicId                  string
	storeId                   string
	name                      string
	description               string
	createTime                time.Time
	updateTime                time.Time
	version                   int
	vaultPath                 string
	username                  string
	keyType                   string
	keyBits                   int
	ttl                       string
	keyId                     string
	criticalOptions           []byte
	extensions                []byte
	credType                  string
	projectId                 string
	additionalValidPrincipals string

	history []vaultSshCertCredLibHistory
}
type vaultSshCertCredLibHistory struct {
	cl         vaultSshCertCredLib
	historyId  string
	validRange string
}

// vaultGenericCredLibMappingOvrd holds database data about a Vault generic
// credential library's mapping override. Not designed to be used outside of
// testBuildTestVaultCredLibRefactorDbData.
type vaultGenericCredLibMappingOvrd struct {
	libraryId        string
	usernameAttr     string
	passwordAttr     string
	domainAttr       string
	pkAttr           string
	pkPassphraseAttr string
}

// rowCounts holds row count information for various database tables and views.
// Not designed to be used outside of testBuildTestVaultCredLibRefactorDbData.
type rowCounts struct {
	// credential_library
	credLib int64
	// credential_library_history_base
	credLibHistory int64
	// credential_vault_library (post-refactor meaning only)
	credVaultLibPostRefactor int64
	// credential_vault_library_mapping_override (pre-refactor) or
	// credential_vault_generic_library_mapping_override
	credVaultGenericLibMappingOvrd int64

	// credential_vault_library (pre-refactor) or
	// credential_vault_generic_library
	credVaultGenericLib int64
	// credential_vault_library_hst (pre-refactor) or
	// credential_vault_generic_library_hst
	credVaultGenericLibHistory int64
	// credential_vault_library_deleted (pre-refactor) or
	// credential_vault_generic_library_deleted
	credVaultGenericLibDeleted int64

	// credential_vault_ssh_cert_library
	credVaultSshCertLib int64
	// credential_vault_ssh_cert_library_hst
	credVaultSshCertLibHistory int64
	// credential_vault_ssh_cert_library_deleted
	credVaultSshCertLibDeleted int64

	// credential_vault_library_username_password_mapping_override
	// (pre-refactor) or
	// credential_vault_generic_library_username_password_mapping_ovrd
	credVaultGenericLibMappingOvrdUserPass int64
	// credential_vault_library_username_password_domain_mapping_ovrd
	// (pre-refactor) or
	// credential_vault_generic_library_usern_pass_domain_mapping_ovrd
	credVaultGenericLibMappingOvrdUserPassDomain int64
	// credential_vault_library_ssh_private_key_mapping_override (pre-refactor)
	// or credential_vault_generic_library_ssh_private_key_mapping_ovrd
	credVaultGenericLibMappingOvrdSshPk int64

	// credential_vault_library_issue_credentials
	credVaultLibIssueCredentials int64

	// credential_vault_library_list_lookup (pre-refactor), or
	// credential_vault_generic_library_list_lookup
	credVaultGenericLibListLookup int64

	// credential_vault_library_hst_aggregate (pre-refactor), or
	// credential_vault_generic_library_hst_aggregate
	credVaultGenericLibHistoryAgg int64

	// whx_credential_dimension_source
	credDimensionSource int64
}

// testVaultCredLibRefactorDbSetupCounts is an input to
// testVaultCredLibRefactorDbSetup that controls the number of
// orgs/projects/credential libraries to create.
type testVaultCredLibRefactorDbSetupCounts struct {
	// orgs is the number of org scopes to create.
	orgs int

	// projectsPerOrg is the number of project scopes to create per org.
	projectsPerOrg int

	// vaultGenericCredLibs is the number of Vault generic credential
	// libraries to create per project.
	vaultGenericCredLibs int

	// vaultGenericCredLibsDeleted is the number of Vault generic credential
	// libraries to delete per project. Note that we create new credential
	// libraries for the purposes of deletion so this doesn't affect
	// vaultGenericCredLibs.
	vaultGenericCredLibsDeleted int

	// vaultSshCertCredLibs is the number of Vault SSH Certificate
	// credential libraries to create per project.
	vaultSshCertCredLibs int

	// vaultSshCertCredLibsDeleted is the number of Vault SSH certificate
	// credential libraries to delete per project. Note that we create new
	// credential libraries for the purposes of deletion so this doesn't affect
	// vaultSshCertCredLibs.
	vaultSshCertCredLibsDeleted int
}
