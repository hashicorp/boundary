package oplog

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/jinzhu/gorm"
)

// Writer interface for Entries
type Writer interface {
	// Create the entry
	Create(interface{}) error

	// Update the entry using the fieldMaskPaths, which are Paths from field_mask.proto
	Update(entry interface{}, fieldMaskPaths []string) error

	// Delete the entry
	Delete(interface{}) error

	// HasTable checks if tableName exists
	hasTable(tableName string) bool

	// CreateTableLike will create a newTableName using the existing table as a starting point
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

// Update an object in storage, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
// we will send every field to the DB.
func (w *GormWriter) Update(i interface{}, fieldMaskPaths []string) error {
	if w.Tx == nil {
		return errors.New("update Tx is nil")
	}
	if i == nil {
		return errors.New("update interface is nil")
	}
	if len(fieldMaskPaths) == 0 {
		if err := w.Tx.Save(i).Error; err != nil {
			return fmt.Errorf("error updating: %w", err)
		}
	}
	updateFields := map[string]interface{}{}

	val := reflect.Indirect(reflect.ValueOf(i))
	structTyp := val.Type()
	for _, field := range fieldMaskPaths {
		for i := 0; i < structTyp.NumField(); i++ {
			// support for an embedded a gorm type
			if structTyp.Field(i).Type.Kind() == reflect.Struct {
				embType := structTyp.Field(i).Type
				// check if the embedded field is exported via CanInterface()
				if val.Field(i).CanInterface() {
					embVal := reflect.Indirect(reflect.ValueOf(val.Field(i).Interface()))
					for embFieldNum := 0; embFieldNum < embType.NumField(); embFieldNum++ {
						if strings.EqualFold(embType.Field(embFieldNum).Name, field) {
							updateFields[field] = embVal.Field(embFieldNum).Interface()
						}
					}
					continue
				}
			}
			// it's not an embedded type, so check if the field name matches
			if strings.EqualFold(structTyp.Field(i).Name, field) {
				updateFields[field] = val.Field(i).Interface()
			}
		}
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

type gormTabler struct {
	tableName string
}

// TableName returns the tabler's table name (it's a gorm pattern for this sort of thing)
// and it has to be exported for Gorm to call it
func (t gormTabler) TableName() string {
	if t.tableName == "" {
		panic("gormTabler must always have a tableName")
	}
	return t.tableName
}

// DropTableIfExists will drop the table if it exists
func (w *GormWriter) dropTableIfExists(tableName string) error {
	if tableName == "" {
		return errors.New("error tableName is empty string for DropTableIfExists")
	}
	return w.Tx.DropTableIfExists(tableName).Error
}
