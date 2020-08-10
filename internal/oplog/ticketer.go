package oplog

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/jinzhu/gorm"
)

var (
	ErrTicketNotFound        = errors.New("ticket not found")
	ErrTicketAlreadyRedeemed = errors.New("ticket already redeemed")
	ErrTicketRedeeming       = errors.New("error trying to redeem ticket")
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
	if tx == nil {
		return nil, errors.New("tx is nil")
	}
	opts := GetOpts(opt...)
	enableAggregateNames := opts[optionWithAggregateNames].(bool)
	return &GormTicketer{tx: tx, withAggregateNames: enableAggregateNames}, nil
}

// GetTicket returns a ticket for the specified name.  You MUST GetTicket in the same transaction
// that you're using to write to the database tables. Names allow us to shard tickets around domain root names
func (ticketer *GormTicketer) GetTicket(aggregateName string) (*store.Ticket, error) {
	if aggregateName == "" {
		return nil, errors.New("bad ticket name")
	}
	name := DefaultAggregateName
	if ticketer.withAggregateNames {
		name = aggregateName
	}
	ticket := store.Ticket{}
	if err := ticketer.tx.First(&ticket, store.Ticket{Name: name}).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, ErrTicketNotFound
		}
		return nil, fmt.Errorf("error retreiving ticket from storage: %w", err)
	}
	return &ticket, nil
}

// Redeem will attempt to redeem the ticket. If the ticket version has already been used, then an error is returned
func (ticketer *GormTicketer) Redeem(t *store.Ticket) error {
	if t == nil {
		return errors.New("ticket is nil")
	}
	tx := ticketer.tx.Model(t).Where("version = ?", t.Version).Update("version", t.Version+1)
	if tx.Error != nil {
		return ErrTicketRedeeming
	}
	if tx.RowsAffected != 1 {
		return ErrTicketAlreadyRedeemed
	}
	return nil
}
