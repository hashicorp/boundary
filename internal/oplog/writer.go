package oplog

import (
	"github.com/jinzhu/gorm"
)

// Writer interface for Entries
type Writer interface {
	// Create an entry in storage
	Create(*Entry) error
}

// GormWriter uses a gorm DB connection for writing
type GormWriter struct {
	Tx *gorm.DB
}

// Create an entry in storage
func (w *GormWriter) Create(e *Entry) error {
	return w.Tx.Create(e).Error
}
