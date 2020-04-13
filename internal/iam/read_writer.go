package iam

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/jinzhu/gorm"
)

type Reader interface {
	LookupByFriendlyName(ctx context.Context, resource interface{}, friendlyName string, opt ...Option) error
	LookupByPublicId(ctx context.Context, resource interface{}, publicId string, opt ...Option) error
	LookupByInternalId(ctx context.Context, resource interface{}, internalId uint32, opt ...Option) error
	LookupBy(ctx context.Context, resource interface{}, where string, args ...interface{}) error
	SearchBy(ctx context.Context, resources interface{}, where string, args ...interface{}) error
}
type Writer interface {
	Update(i interface{}, fieldMaskPaths []string) error
	Create(ctx context.Context, i interface{}) error
	CreateConstraint(tableName string, constraintName string, constraint string) error
}

// Gorm uses a gorm DB connection for writing
type GormReadWriter struct {
	Tx *gorm.DB
}

func (w *GormReadWriter) CreateConstraint(tableName string, constraintName string, constraint string) error {
	return w.Tx.Exec("create_constraint_if_not_exists(?, ?, ?)", tableName, constraintName, constraint).Error
}

// Create an object in storage
func (w *GormReadWriter) Create(ctx context.Context, i interface{}) error {
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
func (w *GormReadWriter) Update(i interface{}, fieldMaskPaths []string) error {
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

func (w *GormReadWriter) LookupByFriendlyName(ctx context.Context, resource interface{}, friendlyName string, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("error db nil for LookupByFriendlyName")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByFriendlyName")
	}
	if friendlyName == "" {
		return errors.New("error friendlyName empty string for LookupByFriendlyName")
	}
	return w.Tx.Where("friendly_name = ?", friendlyName).First(resource).Error
}
func (w *GormReadWriter) LookupByPublicId(ctx context.Context, resource interface{}, publicId string, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("error db nil for LookupByPublicId")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByPublicId")
	}
	if publicId == "" {
		return errors.New("error publicId empty string for LookupByPublicId")
	}
	return w.Tx.Where("public_id = ?", publicId).First(resource).Error
}
func (w *GormReadWriter) LookupByInternalId(ctx context.Context, resource interface{}, internalId uint32, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("error db nil for LookupByInternalId")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByInternalId")
	}
	if internalId == 0 {
		return errors.New("error internalId is 0 for LookupByInternalId")
	}
	return w.Tx.Where("id = ?", internalId).First(resource).Error
}

func (w *GormReadWriter) LookupBy(ctx context.Context, resource interface{}, where string, args ...interface{}) error {
	if w.Tx == nil {
		return errors.New("error db nil for SearchBy")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for SearchBy")
	}
	return w.Tx.Where(where, args...).First(&resource).Error
}
func (w *GormReadWriter) SearchBy(ctx context.Context, resources interface{}, where string, args ...interface{}) error {
	if w.Tx == nil {
		return errors.New("error db nil for SearchBy")
	}
	if reflect.ValueOf(resources).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for SearchBy")
	}
	return w.Tx.Where(where, args...).Find(&resources).Error
}
