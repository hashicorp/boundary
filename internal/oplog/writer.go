package oplog

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/db/common"

	"github.com/jinzhu/gorm"
)

// Writer interface for Entries
type Writer interface {
	// Create the entry
	Create(interface{}) error

	// Update the entry using the fieldMaskPaths and setNullPaths, which are
	// Paths from field_mask.proto.  fieldMaskPaths is required.  setToNullPaths
	// is optional.  fieldMaskPaths and setNullPaths cannot instersect and both
	// cannot be zero len.
	Update(entry interface{}, fieldMaskPaths, setToNullPaths []string) error

	// Delete the entry
	Delete(interface{}) error

	// HasTable checks if tableName exists
	hasTable(tableName string) bool

	// CreateTableLike will create a newTableName using the existing table as a
	// starting point
	createTableLike(existingTableName string, newTableName string) error

	// DropTableIfExists will drop the table if it exists
	dropTableIfExists(tableName string) error
}

// GormWriter uses a gorm DB connection for writing
type GormWriter struct {
	Tx *gorm.DB
}

// Create an object in storage
func (w *GormWriter) Create(i interface{}) error {
	if w.Tx == nil {
		return errors.New("create Tx is nil")
	}
	if i == nil {
		return errors.New("create interface is nil")
	}
	if err := w.Tx.Create(i).Error; err != nil {
		return fmt.Errorf("error creating: %w", err)
	}
	return nil
}

// Update the entry using the fieldMaskPaths and setNullPaths, which are
// Paths from field_mask.proto.  fieldMaskPaths and setNullPaths cannot
// intersect and both cannot be zero len.
func (w *GormWriter) Update(i interface{}, fieldMaskPaths, setToNullPaths []string) error {
	if w.Tx == nil {
		return errors.New("update Tx is nil")
	}
	if i == nil {
		return errors.New("update interface is nil")
	}
	if len(fieldMaskPaths) == 0 && len(setToNullPaths) == 0 {
		return errors.New("update both fieldMaskPaths and setToNullPaths are missing")
	}
	// common.UpdateFields will also check to ensure that fieldMaskPaths and
	// setToNullPaths do not intersect.
	updateFields, err := common.UpdateFields(i, fieldMaskPaths, setToNullPaths)
	if err != nil {
		return fmt.Errorf("error updating: unable to build update fields %w", err)
	}
	if err := w.Tx.Model(i).Updates(updateFields).Error; err != nil {
		return fmt.Errorf("error updating: %w", err)
	}
	return nil
}

// Deleting an object in storage
func (w *GormWriter) Delete(i interface{}) error {
	if w.Tx == nil {
		return errors.New("delete Tx is nil")
	}
	if i == nil {
		return errors.New("delete interface is nil")
	}
	if err := w.Tx.Delete(i).Error; err != nil {
		return fmt.Errorf("error deleting: %w", err)
	}
	return nil
}

// HasTable checks if tableName exists
func (w *GormWriter) hasTable(tableName string) bool {
	if tableName == "" {
		return false
	}
	return w.Tx.Dialect().HasTable(tableName)
}

// CreateTableLike will create a newTableName like the model's table
// the new table should have all things like the existing model's table (defaults, constraints, indexes, etc)
func (w *GormWriter) createTableLike(existingTableName string, newTableName string) error {
	if existingTableName == "" {
		return errors.New("error existingTableName is empty string")
	}
	if newTableName == "" {
		return errors.New("error newTableName is empty string")
	}
	existingTableName = w.Tx.Dialect().Quote(existingTableName)
	newTableName = w.Tx.Dialect().Quote(newTableName)
	var sql string
	switch w.Tx.Dialect().GetName() {
	case "postgres":
		sql = fmt.Sprintf(
			`CREATE TABLE %s ( LIKE %s INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES );`,
			newTableName,
			existingTableName,
		)
	case "mysql":
		sql = fmt.Sprintf("CREATE TABLE %s LIKE %s",
			newTableName,
			existingTableName,
		)
	default:
		return errors.New("error unsupported RDBMS")
	}
	return w.Tx.Exec(sql).Error
}

// DropTableIfExists will drop the table if it exists
func (w *GormWriter) dropTableIfExists(tableName string) error {
	if tableName == "" {
		return errors.New("cannot drop table whose name is an empty string")
	}
	return w.Tx.DropTableIfExists(tableName).Error
}
