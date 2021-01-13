package oplog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_NewGormTicketer provides unit tests for creating a Gorm ticketer
func Test_NewGormTicketer(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		require.NoError(err)
		assert.NotNil(ticketer)
	})
	t.Run("bad db", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := NewGormTicketer(nil, WithAggregateNames(true))
		require.Error(err)
		assert.Equal("oplog.NewGormTicketer: nil tx: parameter violation: error #100", err.Error())
	})
}

// Test_GetTicket provides unit tests for getting oplog.Tickets
func Test_GetTicket(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticket, err := ticketer.GetTicket("default")
		require.NoError(err)
		assert.Equal(ticket.Name, "default")
		assert.NotEqual(ticket.Version, 0)
	})

	t.Run("no name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticket, err := ticketer.GetTicket("")
		require.Error(err)
		assert.Equal("oplog.(GormTicketer).GetTicket: missing ticket name: parameter violation: error #100", err.Error())
		assert.Nil(ticket)
	})
}

// Test_Redeem provides unit tests for redeeming tickets
func Test_Redeem(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	t.Run("valid", func(t *testing.T) {
		require := require.New(t)

		tx := db.Begin()
		defer tx.Commit()
		ticketer, err := NewGormTicketer(tx, WithAggregateNames(true))
		require.NoError(err)

		ticket, err := ticketer.GetTicket("default")
		require.NoError(err)

		err = ticketer.Redeem(ticket)
		require.NoError(err)
	})
	t.Run("nil ticket", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tx := db.Begin()
		defer tx.Commit()

		ticketer, err := NewGormTicketer(tx, WithAggregateNames(true))
		require.NoError(err)
		err = ticketer.Redeem(nil)
		require.Error(err)
		assert.Equal("oplog.(GormTicketer).Redeem: nil ticket: parameter violation: error #100", err.Error())
	})

	t.Run("detect two redemptions in separate concurrent transactions", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tx := db.Begin()
		ticketer, err := NewGormTicketer(tx, WithAggregateNames(true))
		require.NoError(err)

		ticket, err := ticketer.GetTicket("default")
		require.NoError(err)

		secondTx := db.Begin()
		secondTicketer, err := NewGormTicketer(secondTx, WithAggregateNames(true))
		require.NoError(err)
		secondTicket, err := secondTicketer.GetTicket("default")
		require.NoError(err)

		err = ticketer.Redeem(ticket)
		require.NoError(err)
		tx.Commit()

		err = secondTicketer.Redeem(secondTicket)
		assert.Equal("oplog.(GormTicketer).Redeem: ticket already redeemed: integrity violation: error #106", err.Error())
	})
}
