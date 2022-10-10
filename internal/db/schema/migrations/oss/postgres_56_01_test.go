package oss_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_DeleteOrphanedAccounts(t *testing.T) {
	const (
		priorMigration   = 55001
		currentMigration = 56001
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

	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	err = kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(t, err)

	// Create the user we will associate accounts with
	iamRepo := iam.TestRepo(t, conn, wrapper)
	usr, err := iam.NewUser(scope.Global.String())
	require.NoError(t, err)
	usr, err = iamRepo.CreateUser(ctx, usr)
	require.NoError(t, err)

	// Create the accounts we will delete and assert their behavior
	pwRepo, err := password.NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)

	pwAm1, err := password.NewAuthMethod(scope.Global.String())
	require.NoError(t, err)
	pwAm1, err = pwRepo.CreateAuthMethod(ctx, pwAm1)
	require.NoError(t, err)
	pwAcct1, err := password.NewAccount(pwAm1.GetPublicId(), password.WithLoginName("account1"), password.WithPassword("password"))
	require.NoError(t, err)
	pwAcct1, err = pwRepo.CreateAccount(ctx, scope.Global.String(), pwAcct1)
	require.NoError(t, err)

	pwAm2, err := password.NewAuthMethod(scope.Global.String())
	require.NoError(t, err)
	pwAm2, err = pwRepo.CreateAuthMethod(ctx, pwAm2)
	require.NoError(t, err)
	pwAcct2, err := password.NewAccount(pwAm2.GetPublicId(), password.WithLoginName("account2"), password.WithPassword("password"))
	require.NoError(t, err)
	pwAcct2, err = pwRepo.CreateAccount(ctx, scope.Global.String(), pwAcct2)
	require.NoError(t, err)

	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	oidcAm1 := oidc.TestAuthMethod(t, conn, databaseWrapper, scope.Global.String(), oidc.InactiveState, "alice_rp1",
		"my-dogs-name", oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice1.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api1.com")[0]))
	oidcAcct1, err := oidc.NewAccount(ctx, oidcAm1.GetPublicId(), "oidcAcct1")
	require.NoError(t, err)
	oidcAcct1, err = oidcRepo.CreateAccount(ctx, scope.Global.String(), oidcAcct1)
	require.NoError(t, err)
	oidcAm2 := oidc.TestAuthMethod(t, conn, databaseWrapper, scope.Global.String(), oidc.InactiveState, "alice_rp2",
		"my-dogs-name", oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice2.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api2.com")[0]))
	oidcAcct2, err := oidc.NewAccount(ctx, oidcAm2.GetPublicId(), "oidcAcct2")
	require.NoError(t, err)
	oidcAcct2, err = oidcRepo.CreateAccount(ctx, scope.Global.String(), oidcAcct2)
	require.NoError(t, err)

	_, err = iamRepo.AddUserAccounts(ctx, usr.GetPublicId(), usr.GetVersion(),
		[]string{pwAcct1.GetPublicId(), pwAcct2.GetPublicId(),
			oidcAcct1.GetPublicId(), oidcAcct2.GetPublicId()})
	require.NoError(t, err)
	usr, accts, err := iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{pwAcct1.GetPublicId(), pwAcct2.GetPublicId(),
		oidcAcct1.GetPublicId(), oidcAcct2.GetPublicId()}, accts)

	_, err = pwRepo.DeleteAccount(ctx, scope.Global.String(), pwAcct1.GetPublicId())
	require.NoError(t, err)
	_, err = oidcRepo.DeleteAccount(ctx, scope.Global.String(), oidcAcct1.GetPublicId())
	require.NoError(t, err)

	// pwAcct1 is still listed as an account for this user!  oh no!
	_, accts, err = iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{pwAcct1.GetPublicId(), pwAcct2.GetPublicId(),
		oidcAcct1.GetPublicId(), oidcAcct2.GetPublicId()}, accts)

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

	// pwAcct1 is no longer listed as an account for this user.  Phew!
	_, accts, err = iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{pwAcct2.GetPublicId(), oidcAcct2.GetPublicId()}, accts)

	_, err = pwRepo.DeleteAccount(ctx, scope.Global.String(), pwAcct2.GetPublicId())
	require.NoError(t, err)
	_, accts, err = iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{oidcAcct2.GetPublicId()}, accts)
	_, err = oidcRepo.DeleteAccount(ctx, scope.Global.String(), oidcAcct2.GetPublicId())
	require.NoError(t, err)

	// Deleting the account now removes the association with the user
	_, accts, err = iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.Empty(t, accts)
}
