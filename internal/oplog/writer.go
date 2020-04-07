package oplog

import (
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
}

// GormWriter uses a gorm DB connection for writing
type GormWriter struct {
	Tx *gorm.DB
}

// Create an object in storage
func (w *GormWriter) Create(i interface{}) error {
	if err := w.Tx.Create(i).Error; err != nil {
		return fmt.Errorf("error creating: %w", err)
	}
	return nil
}

// Update an object in storage, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
// we will send every field to the DB.
func (w *GormWriter) Update(i interface{}, fieldMaskPaths []string) error {
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
				embVal := reflect.Indirect(reflect.ValueOf(val.Field(i).Interface()))
				for embFieldNum := 0; embFieldNum < embType.NumField(); embFieldNum++ {
					if strings.EqualFold(embType.Field(embFieldNum).Name, field) {
						updateFields[field] = embVal.Field(embFieldNum).Interface()
					}
				}
				continue
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
	if err := w.Tx.Delete(i).Error; err != nil {
		return fmt.Errorf("error deleting: %w", err)
	}
	return nil
}
