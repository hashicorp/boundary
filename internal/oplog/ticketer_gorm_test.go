package oplog

import (
	"testing"

	"github.com/hashicorp/go-uuid"
	"gotest.tools/assert"
)

// Test_NewGormTicketer provides unit tests for creating a Gorm ticketer
func Test_NewGormTicketer(t *testing.T) {
	t.Parallel()
	startTest()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
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
	startTest()
	t.Parallel()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()

	ticketName, err := uuid.GenerateUUID()
	assert.NilError(t, err)
	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	assert.NilError(t, err)

	err = ticketer.InitTicket(ticketName)
	assert.NilError(t, err)

	t.Run("valid", func(t *testing.T) {
		ticket, err := ticketer.GetTicket(ticketName)
		assert.NilError(t, err)
		assert.Equal(t, ticket.Name, ticketName)
		assert.Check(t, ticket.Version != 0)
	})

	t.Run("no name", func(t *testing.T) {
		ticket, err := ticketer.GetTicket("")
		assert.Equal(t, err.Error(), "bad ticket name")
		assert.Check(t, ticket == nil)
	})
}

// Test_InitTicket provides unit tests for initializing tickets
func Test_InitTicket(t *testing.T) {
	startTest()
	t.Parallel()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()

	ticketName, err := uuid.GenerateUUID()
	assert.NilError(t, err)
	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	assert.NilError(t, err)

	t.Run("valid", func(t *testing.T) {
		err = ticketer.InitTicket(ticketName)
		assert.NilError(t, err)
	})

	t.Run("no name", func(t *testing.T) {
		err = ticketer.InitTicket("")
		assert.Equal(t, err.Error(), "bad ticket name")
	})
}

// Test_Redeem provides unit tests for redeeming tickets
func Test_Redeem(t *testing.T) {
	startTest()
	t.Parallel()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()

	ticketName, err := uuid.GenerateUUID()
	assert.NilError(t, err)
	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	assert.NilError(t, err)

	// in it's own transaction, init the ticket
	_ = ticketer.InitTicket(ticketName)

	t.Run("valid", func(t *testing.T) {
		tx := db.Begin()
		ticketer, err := NewGormTicketer(tx, WithAggregateNames(true))
		assert.NilError(t, err)

		ticket, err := ticketer.GetTicket(ticketName)
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

		ticket, err := ticketer.GetTicket(ticketName)
		assert.NilError(t, err)

		secondTx := db.Begin()
		secondTicketer, err := NewGormTicketer(secondTx, WithAggregateNames(true))
		assert.NilError(t, err)
		secondTicket, err := secondTicketer.GetTicket(ticketName)
		assert.NilError(t, err)

		err = ticketer.Redeem(ticket)
		assert.NilError(t, err)
		tx.Commit()

		err = secondTicketer.Redeem(secondTicket)
		assert.Equal(t, err.Error(), "ticket already redeemed")
	})

}
