// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/go-dbw"
)

const DefaultAggregateName = "global"

// Ticketer provides an interface to storage for Tickets, so you can easily substitute your own ticketer
type Ticketer interface {
	// GetTicket returns a ticket for the specified name.  You MUST GetTicket in the same transaction
	// that you're using to write to the database tables. Names allow us to shard tickets around domain root names.
	// Before getting a ticket you must insert it with it's name into the oplog_ticket table.  This is done via a
	// db migrations script.  Requiring this insert as part of migrations ensures that the tickets are initialized in
	// a separate transaction from when a client calls GetTicket(aggregateName) which is critical for the optimized locking
	// pattern to work properly
	GetTicket(ctx context.Context, aggregateName string) (*store.Ticket, error)

	// Redeem ticket will attempt to redeem the ticket and ensure it's serialized with other tickets using the same
	// aggregate name
	Redeem(ctx context.Context, ticket *store.Ticket) error
}

// DbwTicketer defines a ticketer that uses the dbw pkg for database operations.
type DbwTicketer struct {
	tx                 *dbw.DB
	withAggregateNames bool
}

// NewTicketer creates a new ticketer that uses dbw for storage
func NewTicketer(ctx context.Context, tx *dbw.DB, opt ...Option) (*DbwTicketer, error) {
	const op = "oplog.NewDbwTicketer"
	if tx == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil tx")
	}
	opts := GetOpts(opt...)
	enableAggregateNames := opts[optionWithAggregateNames].(bool)
	return &DbwTicketer{tx: tx, withAggregateNames: enableAggregateNames}, nil
}

// GetTicket returns a ticket for the specified name.  You MUST GetTicket in the same transaction
// that you're using to write to the database tables. Names allow us to shard tickets around domain root names
func (ticketer *DbwTicketer) GetTicket(ctx context.Context, aggregateName string) (*store.Ticket, error) {
	const op = "oplog.(GormTicketer).GetTicket"
	if aggregateName == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing ticket name")
	}
	name := DefaultAggregateName
	if ticketer.withAggregateNames {
		name = aggregateName
	}
	ticket := store.Ticket{}
	if err := dbw.New(ticketer.tx).LookupWhere(ctx, &ticket, "name = ?", []any{name}); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, errors.New(ctx, errors.TicketNotFound, op, "ticket not found")
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error retrieving ticket from storage"))
	}
	return &ticket, nil
}

// Redeem will attempt to redeem the ticket. If the ticket version has already been used, then an error is returned
func (ticketer *DbwTicketer) Redeem(ctx context.Context, t *store.Ticket) error {
	const op = "oplog.(GormTicketer).Redeem"
	if t == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil ticket")
	}
	currentVersion := t.Version
	t.Version = t.Version + 1
	rowsUpdated, err := dbw.New(ticketer.tx).Update(ctx, t, []string{"Version"}, nil, dbw.WithVersion(&currentVersion))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error trying to redeem ticket"))
	}
	if rowsUpdated != 1 {
		return errors.New(ctx, errors.TicketAlreadyRedeemed, op, "ticket already redeemed")
	}
	return nil
}
