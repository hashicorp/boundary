package oplog

import (
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"gorm.io/gorm"
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
	GetTicket(aggregateName string) (*store.Ticket, error)

	// Redeem ticket will attempt to redeem the ticket and ensure it's serialized with other tickets using the same
	// aggregate name
	Redeem(ticket *store.Ticket) error
}

// GormTicketer uses a gorm DB connection for ticket storage
type GormTicketer struct {
	tx                 *gorm.DB
	withAggregateNames bool
}

// NewGormTicketer creates a new ticketer that uses gorm for storage
func NewGormTicketer(tx *gorm.DB, opt ...Option) (*GormTicketer, error) {
	const op = "oplog.NewGormTicketer"
	if tx == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil tx")
	}
	opts := GetOpts(opt...)
	enableAggregateNames := opts[optionWithAggregateNames].(bool)
	return &GormTicketer{tx: tx, withAggregateNames: enableAggregateNames}, nil
}

// GetTicket returns a ticket for the specified name.  You MUST GetTicket in the same transaction
// that you're using to write to the database tables. Names allow us to shard tickets around domain root names
func (ticketer *GormTicketer) GetTicket(aggregateName string) (*store.Ticket, error) {
	const op = "oplog.(GormTicketer).GetTicket"
	if aggregateName == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing ticket name")
	}
	name := DefaultAggregateName
	if ticketer.withAggregateNames {
		name = aggregateName
	}
	ticket := store.Ticket{}
	if err := ticketer.tx.First(&ticket, store.Ticket{Name: name}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.NewDeprecated(errors.TicketNotFound, op, "ticket not found")
		}
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("error retrieving ticket from storage"))
	}
	return &ticket, nil
}

// Redeem will attempt to redeem the ticket. If the ticket version has already been used, then an error is returned
func (ticketer *GormTicketer) Redeem(t *store.Ticket) error {
	const op = "oplog.(GormTicketer).Redeem"
	if t == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil ticket")
	}
	tx := ticketer.tx.Model(t).Where("version = ?", t.Version).Update("version", t.Version+1)
	if tx.Error != nil {
		return errors.WrapDeprecated(tx.Error, op, errors.WithMsg("error trying to redeem ticket"))
	}
	if tx.RowsAffected != 1 {
		return errors.NewDeprecated(errors.TicketAlreadyRedeemed, op, "ticket already redeemed")
	}
	return nil
}
