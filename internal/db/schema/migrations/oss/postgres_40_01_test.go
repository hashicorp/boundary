package oss_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_Credential_Purpose_Refactor(t *testing.T) {
	const (
		priorMigration   = 39002
		currentMigration = 40001
	)

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

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(t, err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(t, err)
	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
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
	require.Equal(t, want, state)

	// Get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(t, err)
	conn, err := db.Open(ctx, dbType, u)
	require.NoError(t, err)
	rw := db.New(conn)

	// Create project
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, proj := iam.TestScopes(t, iamRepo)
	kmsCache := kms.TestKms(t, conn, wrapper)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()

	// Create host catalog
	hostCatalogId := "hcst_s1P81LMusN"
	num, err := rw.Exec(ctx, `
insert into static_host_catalog
	(scope_id, public_id, name)
values
	(?, ?, ?)
`, []interface{}{proj.GetPublicId(), hostCatalogId, "my-host-catalog"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create host-set
	hostSetId := "hsst_pff4ao7PjN"
	num, err = rw.Exec(ctx, `
insert into static_host_set
	(public_id, catalog_id)
values
	(?, ?)
`, []interface{}{hostSetId, hostCatalogId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create host
	hostId := "hst_kDvWAAHBx8"
	num, err = rw.Exec(ctx, `
insert into static_host
	(public_id, catalog_id, address)
values
	(?, ?, ?)
`, []interface{}{hostId, hostCatalogId, "0.0.0.0"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Associate host to host-set
	num, err = rw.Exec(ctx, `
insert into static_host_set_member
	(host_id, set_id)
values
	(?, ?)
`, []interface{}{hostId, hostSetId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create a target
	targetId := "ttcp_JunMRz380q"
	num, err = rw.Exec(ctx, `
insert into target_tcp
	(public_id, scope_id, name, session_max_seconds, session_connection_limit)
values
	(?, ?, ?, ?, ?);
`, []interface{}{targetId, proj.GetPublicId(), "my-credential-sources", 28800, -1})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create a credential vault store
	vaultStoreId := "csvlt_vaultid123"
	num, err = rw.Exec(ctx, `
insert into credential_vault_store
  (public_id, scope_id, vault_address)
values
  (?, ?, ?);
`, []interface{}{vaultStoreId, proj.GetPublicId(), "http://vault"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	credLibs := vault.TestCredentialLibraries(t, conn, wrapper, vaultStoreId, 2)
	lib1 := credLibs[0]
	lib2 := credLibs[1]

	// Create static store
	staticStoreId := "csst_staticid123"
	num, err = rw.Exec(ctx, `
insert into credential_static_store
	(public_id, scope_id, name)
values
	(?, ?, ?)
`, []interface{}{staticStoreId, proj.GetPublicId(), "my-static-credential-store"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	credsStatic := static.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", staticStoreId, proj.GetPublicId(), 2)
	cred1 := credsStatic[0]
	cred2 := credsStatic[1]

	appCredLib, err := target.NewCredentialLibrary(targetId, lib1.GetPublicId(), "application")
	require.NoError(t, err)
	egressCredLib, err := target.NewCredentialLibrary(targetId, lib2.GetPublicId(), "egress")
	require.NoError(t, err)
	appCred, err := target.NewStaticCredential(targetId, cred1.PublicId, "application")
	require.NoError(t, err)
	egressCred, err := target.NewStaticCredential(targetId, cred2.PublicId, "egress")
	require.NoError(t, err)

	err = rw.CreateItems(ctx, []interface{}{appCredLib, egressCredLib})
	require.NoError(t, err)
	err = rw.CreateItems(ctx, []interface{}{appCred, egressCred})
	require.NoError(t, err)

	dynCreds := []*session.DynamicCredential{
		session.NewDynamicCredential(appCredLib.GetCredentialLibraryId(), "application"),
		session.NewDynamicCredential(egressCredLib.GetCredentialLibraryId(), "egress"),
	}
	staticCreds := []*session.StaticCredential{
		session.NewStaticCredential(appCred.GetCredentialId(), "application"),
		session.NewStaticCredential(egressCred.GetCredentialId(), "egress"),
	}

	// Associate host-set to target
	num, err = rw.Exec(ctx, `
insert into target_host_set
	(target_id, host_set_id)
values
	(?, ?)
	`, []interface{}{targetId, hostSetId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create a test session
	sessionId := "s_AgLzPhDINE"
	future := time.Now().Add(time.Hour)
	expirationTime := fmt.Sprintf("%v-%d-%v %v:%v:%v.000", future.Year(), future.Month(), future.Day(), future.Hour(), future.Minute(), future.Second())
	_, cert, err := session.TestCert(wrapper, uId, sessionId)
	require.NoError(t, err)
	num, err = rw.Exec(ctx, `
	insert into session
		(public_id, user_id, host_id, target_id, host_set_id, auth_token_id, scope_id, certificate, expiration_time, endpoint)
	values
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, []interface{}{sessionId, uId, hostId, targetId, hostSetId, at.GetPublicId(), proj.GetPublicId(), cert, expirationTime, "tcp://127.0.0.1:22"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	num, err = rw.Exec(ctx, `
insert into session_credential_dynamic
	(session_id, library_id, credential_purpose)
values
	(?, ?, ?),
	(?, ?, ?);
`, []interface{}{
		sessionId, dynCreds[0].LibraryId, dynCreds[0].CredentialPurpose,
		sessionId, dynCreds[1].LibraryId, dynCreds[1].CredentialPurpose,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, num)

	num, err = rw.Exec(ctx, `
insert into session_credential_static
	(session_id, credential_static_id, credential_purpose)
values
	(?, ?, ?),
	(?, ?, ?);
`, []interface{}{
		sessionId, staticCreds[0].CredentialStaticId, staticCreds[0].CredentialPurpose,
		sessionId, staticCreds[1].CredentialStaticId, staticCreds[1].CredentialPurpose,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, num)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(t, err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(t, err)
	state, err = m.CurrentState(ctx)
	require.NoError(t, err)
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
	require.Equal(t, want, state)

	// Validate migrations
	lookupLib := &target.CredentialLibrary{}
	err = rw.LookupWhere(ctx, lookupLib, "credential_library_id = ?", []interface{}{appCredLib.GetCredentialLibraryId()})
	require.NoError(t, err)
	assert.Equal(t, "brokered", lookupLib.CredentialPurpose)

	lookupLib = &target.CredentialLibrary{}
	err = rw.LookupWhere(ctx, lookupLib, "credential_library_id = ?", []interface{}{egressCredLib.GetCredentialLibraryId()})
	require.NoError(t, err)
	assert.Equal(t, "injected_application", lookupLib.CredentialPurpose)

	lookupCred := &target.StaticCredential{}
	err = rw.LookupWhere(ctx, lookupCred, "credential_static_id = ?", []interface{}{appCred.GetCredentialId()})
	require.NoError(t, err)
	assert.Equal(t, "brokered", lookupCred.CredentialPurpose)

	lookupCred = &target.StaticCredential{}
	err = rw.LookupWhere(ctx, lookupCred, "credential_static_id = ?", []interface{}{egressCred.GetCredentialId()})
	require.NoError(t, err)
	assert.Equal(t, "injected_application", lookupCred.CredentialPurpose)

	lookupDynCred := &session.DynamicCredential{}
	err = rw.LookupWhere(ctx, lookupDynCred, "session_id = ? and library_id = ?", []interface{}{sessionId, appCredLib.GetCredentialLibraryId()})
	require.NoError(t, err)
	assert.Equal(t, "brokered", lookupDynCred.CredentialPurpose)

	lookupDynCred = &session.DynamicCredential{}
	err = rw.LookupWhere(ctx, lookupDynCred, "session_id = ? and library_id = ?", []interface{}{sessionId, egressCredLib.GetCredentialLibraryId()})
	require.NoError(t, err)
	assert.Equal(t, "injected_application", lookupDynCred.CredentialPurpose)

	lookupStaticCred := &session.StaticCredential{}
	err = rw.LookupWhere(ctx, lookupStaticCred, "session_id = ? and credential_static_id = ?", []interface{}{sessionId, appCred.GetCredentialId()})
	require.NoError(t, err)
	assert.Equal(t, "brokered", lookupStaticCred.CredentialPurpose)

	lookupStaticCred = &session.StaticCredential{}
	err = rw.LookupWhere(ctx, lookupStaticCred, "session_id = ? and credential_static_id = ?", []interface{}{sessionId, egressCred.GetCredentialId()})
	require.NoError(t, err)
	assert.Equal(t, "injected_application", lookupStaticCred.CredentialPurpose)
}
