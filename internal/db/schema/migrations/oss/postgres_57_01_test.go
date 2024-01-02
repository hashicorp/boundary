// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


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
		priorMigration   = 56001
		currentMigration = 57001
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
	usr, err := iam.NewUser(ctx, scope.Global.String())
	require.NoError(t, err)
	usr.PublicId = "u_1234567890"
	num, err := rw.Exec(ctx, `
insert into iam_user
	(public_id, scope_id)
values
	(?, ?)
	`, []any{usr.PublicId, scope.Global.String()})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create the accounts we will delete and assert their behavior

	pwAm1, err := password.NewAuthMethod(ctx, scope.Global.String())
	require.NoError(t, err)
	pwAm1.PublicId = "ampw_1234567890"
	_, err = rw.DoTx(ctx, 0, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		_, err := w.Exec(ctx, `
		insert into auth_password_argon2_conf
			(private_id, password_method_id)
		values
			(?, ?)
			`, []any{"arg2conf_1234567890", pwAm1.PublicId})
		if err != nil {
			return err
		}
		_, err = w.Exec(ctx, `
		insert into auth_password_method
			(public_id, password_conf_id, scope_id)
		values
			(?, ?, ?)
			`, []any{pwAm1.PublicId, "arg2conf_1234567890", pwAm1.ScopeId})
		return err
	})
	require.NoError(t, err)
	pwAcct1, err := password.NewAccount(ctx, pwAm1.GetPublicId(), password.WithLoginName("account1"), password.WithPassword("password"))
	require.NoError(t, err)
	pwAcct1.PublicId = "acctpw_1234567890"
	num, err = rw.Exec(ctx, `
insert into auth_password_account
	(public_id, auth_method_id, scope_id, login_name)
values
	(?, ?, ?, ?)
	`, []any{pwAcct1.PublicId, pwAm1.PublicId, pwAm1.ScopeId, pwAcct1.LoginName})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	pwAm2, err := password.NewAuthMethod(ctx, scope.Global.String())
	require.NoError(t, err)
	pwAm2.PublicId = "ampw_0123456789"
	_, err = rw.DoTx(ctx, 0, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		_, err := w.Exec(ctx, `
		insert into auth_password_argon2_conf
			(private_id, password_method_id)
		values
			(?, ?)
			`, []any{"arg2conf_0123456789", pwAm2.PublicId})
		if err != nil {
			return err
		}
		_, err = w.Exec(ctx, `
		insert into auth_password_method
			(public_id, password_conf_id, scope_id)
		values
			(?, ?, ?)
			`, []any{pwAm2.PublicId, "arg2conf_0123456789", pwAm2.ScopeId})
		return err
	})
	pwAcct2, err := password.NewAccount(ctx, pwAm2.GetPublicId(), password.WithLoginName("account2"), password.WithPassword("password"))
	require.NoError(t, err)
	pwAcct2.PublicId = "acctpw_0123456789"
	num, err = rw.Exec(ctx, `
insert into auth_password_account
	(public_id, auth_method_id, scope_id, login_name)
values
	(?, ?, ?, ?)
	`, []any{pwAcct2.PublicId, pwAm2.PublicId, pwAm2.ScopeId, pwAcct2.LoginName})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	oidcAm1 := oidc.TestAuthMethod(t, conn, databaseWrapper, scope.Global.String(), oidc.InactiveState, "alice_rp1",
		"my-dogs-name", oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice1.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api1.com")[0]))
	oidcAm1.PublicId = "amoidc_1234567890"
	num, err = rw.Exec(ctx, `
	insert into auth_oidc_method
		(public_id, scope_id, state, key_id)
	values
		(?, ?, ?, ?)
		`, []any{oidcAm1.PublicId, oidcAm1.ScopeId, oidcAm1.OperationalState, oidcAm1.KeyId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	oidcAcct1, err := oidc.NewAccount(ctx, oidcAm1.GetPublicId(), "oidcAcct1")
	require.NoError(t, err)
	oidcAcct1.PublicId = "acctoidc_0123456789"
	num, err = rw.Exec(ctx, `
insert into auth_oidc_account
	(public_id, auth_method_id, scope_id, issuer, subject)
values
	(?, ?, ?, ?, ?)
	`, []any{oidcAcct1.PublicId, oidcAm1.PublicId, oidcAm1.ScopeId, oidcAm1.Issuer, oidcAcct1.Subject})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	oidcAm2 := oidc.TestAuthMethod(t, conn, databaseWrapper, scope.Global.String(), oidc.InactiveState, "alice_rp2",
		"my-dogs-name", oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice2.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api2.com")[0]))
	oidcAm2.PublicId = "amoidc_0123456789"
	num, err = rw.Exec(ctx, `
	insert into auth_oidc_method
		(public_id, scope_id, state, key_id)
	values
		(?, ?, ?, ?)
		`, []any{oidcAm2.PublicId, oidcAm2.ScopeId, oidcAm2.OperationalState, oidcAm2.KeyId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	oidcAcct2, err := oidc.NewAccount(ctx, oidcAm2.GetPublicId(), "oidcAcct2")
	require.NoError(t, err)
	oidcAcct2.PublicId = "acctoidc_1234567890"
	num, err = rw.Exec(ctx, `
insert into auth_oidc_account
	(public_id, auth_method_id, scope_id, issuer, subject)
values
	(?, ?, ?, ?, ?)
	`, []any{oidcAcct2.PublicId, oidcAm2.PublicId, oidcAm2.ScopeId, oidcAm2.Issuer, oidcAcct2.Subject})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	num, err = rw.Exec(ctx, `
update auth_account set 
	iam_user_id=?
where
	public_id in (?, ?, ?, ?)
	`, []any{
		usr.PublicId,
		pwAcct1.PublicId, pwAcct2.PublicId, oidcAcct1.PublicId, oidcAcct2.PublicId,
	})
	require.NoError(t, err)
	assert.Equal(t, 4, num)
	usr, accts, err := iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		pwAcct1.GetPublicId(), pwAcct2.GetPublicId(),
		oidcAcct1.GetPublicId(), oidcAcct2.GetPublicId(),
	}, accts)

	num, err = rw.Exec(ctx, `
delete from auth_password_account
where
	public_id=?
	`, []any{pwAcct1.PublicId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	num, err = rw.Exec(ctx, `
delete from auth_oidc_account
where
	public_id=?
	`, []any{oidcAcct1.PublicId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// pwAcct1 is still listed as an account for this user!  oh no!
	_, accts, err = iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		pwAcct1.GetPublicId(), pwAcct2.GetPublicId(),
		oidcAcct1.GetPublicId(), oidcAcct2.GetPublicId(),
	}, accts)

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

	num, err = rw.Exec(ctx, `
delete from auth_password_account
where
	public_id=?
	`, []any{pwAcct2.PublicId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)
	_, accts, err = iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{oidcAcct2.GetPublicId()}, accts)
	num, err = rw.Exec(ctx, `
delete from auth_oidc_account
where
	public_id=?
	`, []any{oidcAcct2.PublicId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Deleting the account now removes the association with the user
	_, accts, err = iamRepo.LookupUser(ctx, usr.GetPublicId())
	require.NoError(t, err)
	assert.Empty(t, accts)
}
