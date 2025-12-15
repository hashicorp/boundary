// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"context"
	"testing"

	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_NewGormTicketer provides unit tests for creating a Gorm ticketer
func Test_NewTicketer(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
		require.NoError(err)
		assert.NotNil(ticketer)
	})
	t.Run("bad db", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := NewTicketer(testCtx, nil, WithAggregateNames(true))
		require.Error(err)
		assert.Contains(err.Error(), "nil tx: parameter violation: error #100")
	})
}

// Test_GetTicket provides unit tests for getting oplog.Tickets
func Test_GetTicket(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)

	ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticket, err := ticketer.GetTicket(testCtx, "default")
		require.NoError(err)
		assert.Equal(ticket.Name, "default")
		assert.NotEqual(ticket.Version, 0)
	})

	t.Run("no name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticket, err := ticketer.GetTicket(testCtx, "")
		require.Error(err)
		assert.Contains(err.Error(), "missing ticket name: parameter violation: error #100")
		assert.Nil(ticket)
	})
}

// Test_Redeem provides unit tests for redeeming tickets
func Test_Redeem(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)

	t.Run("valid", func(t *testing.T) {
		require := require.New(t)

		tx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer func() {
			assert.NoError(t, tx.Commit(testCtx))
		}()
		ticketer, err := NewTicketer(testCtx, tx.DB(), WithAggregateNames(true))
		require.NoError(err)

		ticket, err := ticketer.GetTicket(testCtx, "default")
		require.NoError(err)

		err = ticketer.Redeem(testCtx, ticket)
		require.NoError(err)
	})
	t.Run("nil ticket", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer func() {
			assert.NoError(tx.Commit(testCtx))
		}()

		ticketer, err := NewTicketer(testCtx, tx.DB(), WithAggregateNames(true))
		require.NoError(err)
		err = ticketer.Redeem(testCtx, nil)
		require.Error(err)
		assert.Contains(err.Error(), "nil ticket: parameter violation: error #100")
	})

	t.Run("detect two redemptions in separate concurrent transactions", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		ticketer, err := NewTicketer(testCtx, tx.DB(), WithAggregateNames(true))
		require.NoError(err)

		ticket, err := ticketer.GetTicket(testCtx, "default")
		require.NoError(err)

		secondTx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		secondTicketer, err := NewTicketer(testCtx, secondTx.DB(), WithAggregateNames(true))
		require.NoError(err)
		secondTicket, err := secondTicketer.GetTicket(testCtx, "default")
		require.NoError(err)

		err = ticketer.Redeem(testCtx, ticket)
		require.NoError(err)
		assert.NoError(tx.Commit(testCtx))

		err = secondTicketer.Redeem(testCtx, secondTicket)
		assert.Contains(err.Error(), "ticket already redeemed: integrity violation: error #106")
	})
}
