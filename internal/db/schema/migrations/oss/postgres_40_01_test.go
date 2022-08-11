package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	hoststatic "github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
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

	require.NoError(t, m.ApplyMigrations(ctx))
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
	hc := hoststatic.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := hoststatic.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := hoststatic.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	hoststatic.TestSetMembers(t, conn, hs.GetPublicId(), []*hoststatic.Host{h})

	// Create a target
	tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, "my-credential-sources", target.WithHostSources([]string{hs.GetPublicId()}))

	vaultStoreId := "csvlt_vaultid123"
	num, err := rw.Exec(ctx, `
insert into credential_vault_store
  (public_id, scope_id, vault_address)
values
  ($1, $2, $3);
`, []interface{}{vaultStoreId, proj.GetPublicId(), "http://vault"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	credLibs := vault.TestCredentialLibraries(t, conn, wrapper, vaultStoreId, 2)
	lib1 := credLibs[0]
	lib2 := credLibs[1]

	storeStatic := static.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	credsStatic := static.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", storeStatic.GetPublicId(), proj.GetPublicId(), 2)
	cred1 := credsStatic[0]
	cred2 := credsStatic[1]

	appCredLib, err := target.NewCredentialLibrary(tar.GetPublicId(), lib1.GetPublicId(), "application")
	require.NoError(t, err)
	egressCredLib, err := target.NewCredentialLibrary(tar.GetPublicId(), lib2.GetPublicId(), "egress")
	require.NoError(t, err)
	appCred, err := target.NewStaticCredential(tar.GetPublicId(), cred1.PublicId, "application")
	require.NoError(t, err)
	egressCred, err := target.NewStaticCredential(tar.GetPublicId(), cred2.PublicId, "egress")
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

	// Create a test session
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:             uId,
		HostId:             h.GetPublicId(),
		TargetId:           tar.GetPublicId(),
		HostSetId:          hs.GetPublicId(),
		AuthTokenId:        at.GetPublicId(),
		ScopeId:            proj.GetPublicId(),
		Endpoint:           "tcp://127.0.0.1:22",
		DynamicCredentials: dynCreds,
		StaticCredentials:  staticCreds,
	})

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(t, err)

	require.NoError(t, m.ApplyMigrations(ctx))
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
	err = rw.LookupWhere(ctx, lookupDynCred, "session_id = ? and library_id = ?", []interface{}{sess.GetPublicId(), appCredLib.GetCredentialLibraryId()})
	require.NoError(t, err)
	assert.Equal(t, "brokered", lookupDynCred.CredentialPurpose)

	lookupDynCred = &session.DynamicCredential{}
	err = rw.LookupWhere(ctx, lookupDynCred, "session_id = ? and library_id = ?", []interface{}{sess.GetPublicId(), egressCredLib.GetCredentialLibraryId()})
	require.NoError(t, err)
	assert.Equal(t, "injected_application", lookupDynCred.CredentialPurpose)

	lookupStaticCred := &session.StaticCredential{}
	err = rw.LookupWhere(ctx, lookupStaticCred, "session_id = ? and credential_static_id = ?", []interface{}{sess.GetPublicId(), appCred.GetCredentialId()})
	require.NoError(t, err)
	assert.Equal(t, "brokered", lookupStaticCred.CredentialPurpose)

	lookupStaticCred = &session.StaticCredential{}
	err = rw.LookupWhere(ctx, lookupStaticCred, "session_id = ? and credential_static_id = ?", []interface{}{sess.GetPublicId(), egressCred.GetCredentialId()})
	require.NoError(t, err)
	assert.Equal(t, "injected_application", lookupStaticCred.CredentialPurpose)
}
