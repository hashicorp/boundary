package oplog

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/jinzhu/gorm"
)

// Ticketer provides an interface to storage for Tickets, so you can easily substitute your own ticketer
type Ticketer interface {
	InitTicket(aggregateName string) (*store.Ticket, error)
	GetTicket(aggregateName string) (*store.Ticket, error)
	Redeem(ticket *store.Ticket) error
}

// GormTicketer uses a gorm DB connection for ticket storage
type GormTicketer struct {
	Tx *gorm.DB
}

// GetTicket returns a ticket for the specified name.  Names allow us to shard tickets around domain root names
func (ticketer *GormTicketer) GetTicket(aggregateName string) (*store.Ticket, error) {
	if aggregateName == "" {
		return nil, fmt.Errorf("bad ticket name")
	}
	ticket := store.Ticket{Name: aggregateName, Version: 1}
	if err := ticketer.Tx.First(&ticket, store.Ticket{Name: aggregateName}).Error; err != nil {
		return nil, err
	}
	return &ticket, nil
}

// InitTicket must happen first in it's own transaction... then you can get a ticket and write to the oplog
func (ticketer *GormTicketer) InitTicket(aggregateName string) (*store.Ticket, error) {
	if aggregateName == "" {
		return nil, fmt.Errorf("bad ticket name")
	}
	ticket := store.Ticket{Name: aggregateName, Version: 1}
	if err := ticketer.Tx.Create(&ticket).Error; err != nil {
		return nil, err
	}
	return &ticket, nil
}

// Redeem will attempt to redeem the ticket. If the ticket version has already been used, then an error is returned
func (ticketer *GormTicketer) Redeem(t *store.Ticket) error {
	tx := ticketer.Tx.Model(t).Where("version = ?", t.Version).Update("version", t.Version+1)
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return fmt.Errorf("EntryTicket.Redeem: ticket number update failed - no rows affected")
	}
	return nil
}
