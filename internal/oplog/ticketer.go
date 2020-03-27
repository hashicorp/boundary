package oplog

import (
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/jinzhu/gorm"
)

const DefaultAggregateName = "global"

// Ticketer provides an interface to storage for Tickets, so you can easily substitute your own ticketer
type Ticketer interface {
	InitTicket(aggregateName string) (*store.Ticket, error)
	GetTicket(aggregateName string) (*store.Ticket, error)
	Redeem(ticket *store.Ticket) error
}

// GormTicketer uses a gorm DB connection for ticket storage
type GormTicketer struct {
	tx                 *gorm.DB
	withAggregateNames bool
}

func NewGormTicketer(tx *gorm.DB, opt ...Option) *GormTicketer {
	opts := GetOpts(opt...)
	enableAggregateNames := opts[optionWithAggregateNames].(bool)
	return &GormTicketer{tx: tx, withAggregateNames: enableAggregateNames}
}

// GetTicket returns a ticket for the specified name.  Names allow us to shard tickets around domain root names
func (ticketer *GormTicketer) GetTicket(aggregateName string) (*store.Ticket, error) {
	if aggregateName == "" {
		return nil, errors.New("bad ticket name")
	}
	name := DefaultAggregateName
	if ticketer.withAggregateNames {
		name = aggregateName
	}
	ticket := store.Ticket{Name: name, Version: 1}
	if err := ticketer.tx.First(&ticket, store.Ticket{Name: name}).Error; err != nil {
		return nil, fmt.Errorf("error retreiving ticket from storage: %w", err)
	}
	return &ticket, nil
}

// InitTicket must happen first in its own transaction... then you can get a ticket and write to the oplog
func (ticketer *GormTicketer) InitTicket(aggregateName string) (*store.Ticket, error) {
	if aggregateName == "" {
		return nil, fmt.Errorf("bad ticket name")
	}
	name := DefaultAggregateName
	if ticketer.withAggregateNames {
		name = aggregateName
	}
	ticket := store.Ticket{Name: name, Version: 1}

	err := ticketer.tx.First(&ticket, store.Ticket{Name: name}).Error
	// no err, so we found an existing ticket, then return it for use
	if err == nil {
		return &ticket, nil
	}
	// there was an error and it wasn't simply a not found error
	if err != nil && !gorm.IsRecordNotFoundError(err) {
		return nil, fmt.Errorf("error retreiving ticket from storage: %w", err)
	}

	// no existing ticket found, so let's create a new one
	if err := ticketer.tx.Create(&ticket).Error; err != nil {
		return nil, fmt.Errorf("error creating ticket in storage: %w", err)
	}
	return &ticket, nil
}

// Redeem will attempt to redeem the ticket. If the ticket version has already been used, then an error is returned
func (ticketer *GormTicketer) Redeem(t *store.Ticket) error {
	tx := ticketer.tx.Model(t).Where("version = ?", t.Version).Update("version", t.Version+1)
	if tx.Error != nil {
		return fmt.Errorf("error redeeming ticket: %w", tx.Error)
	}
	if tx.RowsAffected != 1 {
		return errors.New("EntryTicket.Redeem: ticket number update failed - no rows affected")
	}
	return nil
}
