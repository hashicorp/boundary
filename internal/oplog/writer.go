package oplog

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
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
	const op = "oplog.(GormWriter).Create"
	if w.Tx == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil tx")
	}
	if i == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil interface")
	}
	if err := w.Tx.Create(i).Error; err != nil {
		return errors.WrapDeprecated(err, op)
	}
	return nil
}

// Update the entry using the fieldMaskPaths and setNullPaths, which are
// Paths from field_mask.proto.  fieldMaskPaths and setNullPaths cannot
// intersect and both cannot be zero len.
func (w *GormWriter) Update(i interface{}, fieldMaskPaths, setToNullPaths []string) error {
	const op = "oplog.(GormWriter).Update"
	if w.Tx == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil tx")
	}
	if i == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil interface")
	}
	if len(fieldMaskPaths) == 0 && len(setToNullPaths) == 0 {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing field mask paths and set to null paths")
	}
	// common.UpdateFields will also check to ensure that fieldMaskPaths and
	// setToNullPaths do not intersect.
	updateFields, err := common.UpdateFields(i, fieldMaskPaths, setToNullPaths)
	if err != nil {
		return errors.WrapDeprecated(err, op, errors.WithMsg("unable to build update fields"))
	}
	if err := w.Tx.Model(i).Updates(updateFields).Error; err != nil {
		return errors.WrapDeprecated(err, op)
	}
	return nil
}

// Deleting an object in storage
func (w *GormWriter) Delete(i interface{}) error {
	const op = "oplog.(GormWriter).Delete"
	if w.Tx == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil tx")
	}
	if i == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil interface")
	}
	if err := w.Tx.Delete(i).Error; err != nil {
		return errors.WrapDeprecated(err, op)
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
	const op = "oplog.(GormWriter).createTableLike"
	if existingTableName == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing existing table name")
	}
	if newTableName == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing new table name")
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
		return errors.NewDeprecated(errors.InvalidParameter, op, "unsupported RDBMS")
	}
	err := w.Tx.Exec(sql).Error
	if err != nil {
		return errors.WrapDeprecated(err, op)
	}
	return nil
}

// DropTableIfExists will drop the table if it exists
func (w *GormWriter) dropTableIfExists(tableName string) error {
	const op = "oplog.(GormWriter).dropTableIfExists"
	if tableName == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing table name")
	}
	err := w.Tx.DropTableIfExists(tableName).Error
	if err != nil {
		return errors.WrapDeprecated(err, op)
	}
	return nil
}
