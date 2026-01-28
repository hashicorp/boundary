// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/testing/dbtest"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrations_OplogKeyConversion: in this test we'll create a "deprecated"
// kms (where all the deks are in one set of tables), then we'll create keys in
// that kms.  After that, we'll create a new style kms (where the oplog deks are
// in separate tables), and we'll read the existing deks.  Finally, we'll ensure
// that the orig deks created using the deprecated kms match the deks read from
// the new style kms.  If that's successful, we've converted the oplog deks from
// a shared table table space into their own set of tables.
func TestMigrations_OplogKeyConversion(t *testing.T) {
	const (
		priorMigration   = 76001
		currentMigration = 77004
	)

	t.Parallel()
	testCtx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(testCtx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(t, err)

	_, err = m.ApplyMigrations(testCtx)
	require.NoError(t, err)
	state, err := m.CurrentState(testCtx)
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
	conn, err := db.Open(testCtx, dbType, u)
	require.NoError(t, err)

	rootWrapper := db.TestWrapper(t)

	// recreate the deprecated kms, where all the DEKs are in the same tables.
	deprecatedKms := deprecatedKms(t, conn, rootWrapper)
	deprecatedCreateKeys(t, deprecatedKms, "global")
	origDeks := make([]wrapping.Wrapper, 0, len(kms.ValidDekPurposes()))
	for _, p := range kms.ValidDekPurposes() {
		w, err := deprecatedKms.GetWrapper(testCtx, "global", wrappingKms.KeyPurpose(p.String()))
		require.NoError(t, err)
		origDeks = append(origDeks, w)
	}

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(testCtx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(t, err)

	_, err = m.ApplyMigrations(testCtx)
	require.NoError(t, err)
	state, err = m.CurrentState(testCtx)
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

	// create a new internal kms, where the oplog deks are in their own tables.
	// Then we'll read the existing DEKs and make sure they match the original DEKs
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	newDeks := make([]wrapping.Wrapper, 0, len(kms.ValidDekPurposes()))
	for _, p := range kms.ValidDekPurposes() {
		w, err := kmsCache.GetWrapper(testCtx, "global", p)
		require.NoError(t, err)
		newDeks = append(newDeks, w)
	}
	assert.Equal(t, origDeks, newDeks)
}

// deprecatedKms will create a kms that mimics the deprecated kms where all
// the DEKs are in the same tables
func deprecatedKms(t *testing.T, conn *db.DB, rootWrapper wrapping.Wrapper) *wrappingKms.Kms {
	t.Helper()

	purposes := make([]wrappingKms.KeyPurpose, 0, len(kms.ValidDekPurposes()))
	for _, p := range kms.ValidDekPurposes() {
		purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
	}
	purposes = append(purposes,
		wrappingKms.KeyPurpose(kms.KeyPurposeWorkerAuth.String()),
		wrappingKms.KeyPurpose(kms.KeyPurposeWorkerAuthStorage.String()),
		wrappingKms.KeyPurpose(kms.KeyPurposeRecovery.String()),
		wrappingKms.KeyPurpose(kms.KeyPurposeBsr.String()),
	)
	rw := db.New(conn)

	k, err := wrappingKms.New(db.NewChangeSafeDbwReader(rw), db.NewChangeSafeDbwWriter(rw), purposes)
	require.NoError(t, err)
	err = k.AddExternalWrapper(context.Background(), wrappingKms.KeyPurposeRootKey, rootWrapper)
	require.NoError(t, err)

	return k
}

// deprecatedCreateKeys will create deks that are all in the same table
func deprecatedCreateKeys(t *testing.T, k *wrappingKms.Kms, scopeId string) {
	t.Helper()
	require.NotEmpty(t, scopeId)
	purposes := make([]wrappingKms.KeyPurpose, 0, len(kms.ValidDekPurposes()))
	for _, p := range kms.ValidDekPurposes() {
		purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
	}
	err := k.CreateKeys(context.Background(), scopeId, purposes)
	require.NoError(t, err)
}
