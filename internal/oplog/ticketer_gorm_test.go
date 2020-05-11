package oplog

import (
	"testing"

	"gotest.tools/assert"
)

// Test_NewGormTicketer provides unit tests for creating a Gorm ticketer
func Test_NewGormTicketer(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		assert.NilError(t, err)
		assert.Assert(t, ticketer != nil)
	})
	t.Run("bad db", func(t *testing.T) {
		_, err := NewGormTicketer(nil, WithAggregateNames(true))
		assert.Equal(t, err.Error(), "tx is nil")
	})
}

// Test_GetTicket provides unit tests for getting oplog.Tickets
func Test_GetTicket(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
	defer db.Close()
	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	assert.NilError(t, err)

	t.Run("valid", func(t *testing.T) {
		ticket, err := ticketer.GetTicket("default")
		assert.NilError(t, err)
		assert.Equal(t, ticket.Name, "default")
		assert.Check(t, ticket.Version != 0)
	})

	t.Run("no name", func(t *testing.T) {
		ticket, err := ticketer.GetTicket("")
		assert.Equal(t, err.Error(), "bad ticket name")
		assert.Check(t, ticket == nil)
	})
}

// Test_Redeem provides unit tests for redeeming tickets
func Test_Redeem(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		tx := db.Begin()
		ticketer, err := NewGormTicketer(tx, WithAggregateNames(true))
		assert.NilError(t, err)

		ticket, err := ticketer.GetTicket("default")
		assert.NilError(t, err)

		err = ticketer.Redeem(ticket)
		assert.NilError(t, err)
		tx.Commit()
	})

	t.Run("nil ticket", func(t *testing.T) {
		tx := db.Begin()
		ticketer, err := NewGormTicketer(tx, WithAggregateNames(true))
		assert.NilError(t, err)
		err = ticketer.Redeem(nil)
		assert.Equal(t, err.Error(), "ticket is nil")
		tx.Commit()
	})

	t.Run("detect two redemptions in separate concurrent transactions", func(t *testing.T) {
		tx := db.Begin()
		ticketer, err := NewGormTicketer(tx, WithAggregateNames(true))
		assert.NilError(t, err)

		ticket, err := ticketer.GetTicket("default")
		assert.NilError(t, err)

		secondTx := db.Begin()
		secondTicketer, err := NewGormTicketer(secondTx, WithAggregateNames(true))
		assert.NilError(t, err)
		secondTicket, err := secondTicketer.GetTicket("default")
		assert.NilError(t, err)

		err = ticketer.Redeem(ticket)
		assert.NilError(t, err)
		tx.Commit()

		err = secondTicketer.Redeem(secondTicket)
		assert.Equal(t, err.Error(), "ticket already redeemed")
	})

}
