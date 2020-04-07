package oplog

import (
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/oplog/store"
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
	// InitTicket initializes a ticket.  You MUST initialize a ticket in its own transaction (and commit it),
	// before you GetTicket in a later transaction to write to the oplog.  InitTicket will check to see if
	// the ticket has already been initialized before creating a new one.
	InitTicket(aggregateName string) error

	// GetTicket returns a ticket for the specified name.  You MUST GetTicket in the same transaction
	// that you're using to write to the database tables. Names allow us to shard tickets around domain root names
	GetTicket(aggregateName string) (*store.Ticket, error)

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

// InitTicket initializes a ticket.  You MUST initialize a ticket in its own transaction (and commit it),
// before you GetTicket in a later transaction to write to the oplog.  InitTicket will check to see if
// the ticket has already been initialized before creating a new one.
func (ticketer *GormTicketer) InitTicket(aggregateName string) error {
	// no existing ticket found, so let's initialize a new one
	if aggregateName == "" {
		return fmt.Errorf("bad ticket name")
	}
	// check to see if a ticket has already been initialized
	existingTicket, err := ticketer.GetTicket(aggregateName)
	if err == nil && existingTicket != nil {
		return nil // found an existing intialized ticket without errors
	}
	if err != ErrTicketNotFound {
		return fmt.Errorf("error retreiving ticket from storage: %w", err)
	}

	name := DefaultAggregateName
	if ticketer.withAggregateNames {
		name = aggregateName
	}
	newTicket := store.Ticket{Name: name, Version: 1}
	if err := ticketer.tx.Create(&newTicket).Error; err != nil {
		return fmt.Errorf("error creating ticket in storage: %w", err)
	}
	return nil
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
