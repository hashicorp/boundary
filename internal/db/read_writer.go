package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/jinzhu/gorm"
	"google.golang.org/protobuf/proto"
)

type Reader interface {
	// LookupByFriendlyName will lookup resource my its friendly_name which must be unique
	LookupByFriendlyName(ctx context.Context, resource ResourceWithFriendlyName, opt ...Option) error

	// LookupByPublicId will lookup resource my its public_id which must be unique
	LookupByPublicId(ctx context.Context, resource ResourceWithPublicId, opt ...Option) error

	// LookupById will lookup resource my its internal id which must be unique
	LookupById(ctx context.Context, resource ResourceWithId, opt ...Option) error

	// LookupBy will lookup the first resource using a where clause with parameters (it only returns the first one)
	LookupBy(ctx context.Context, resource interface{}, where string, args ...interface{}) error

	// SearchBy will search for all the resources it can find using a where clause with parameters
	SearchBy(ctx context.Context, resources interface{}, where string, args ...interface{}) error

	// DB returns the sql.DB
	DB() (*sql.DB, error)

	// Dialect returns the RDBMS dialect: postgres, mysql, etc
	Dialect() (string, error)
}
type Writer interface {
	// Update an object in the db, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
	// it will send every field to the DB
	Update(ctx context.Context, i interface{}, fieldMaskPaths []string, opt ...Option) error

	// Create an object in the db with options: WithOplog (which requires WithMetadata, WithWrapper)
	Create(ctx context.Context, i interface{}, opt ...Option) error

	// CreateConstraint will create a db constraint if it doesn't already exist
	CreateConstraint(tableName string, constraintName string, constraint string) error

	// DB returns the sql.DB
	DB() (*sql.DB, error)

	// Dialect returns the RDBMS dialect: postgres, mysql, etc
	Dialect() (string, error)
}

// ResourceWithPublicId defines an interface that LookupByPublicId() can use to get the resource's public id
type ResourceWithPublicId interface {
	GetPublicId() string
}

// ResourceWithFriendlyName defines an interface that LookupByFriendlyName() can use to get the resource's friendly name
type ResourceWithFriendlyName interface {
	GetFriendlyName() string
}

// ResourceWithId defines an interface that LookupById() can use to get the resource's internal id
type ResourceWithId interface {
	GetId() uint32
}

// VetForWriter provides an interface that Create and Update can use to vet the resource before sending it to the db
type VetForWriter interface {
	VetForWrite() error
}

// GormReadWriter uses a gorm DB connection for read/write
type GormReadWriter struct {
	Tx *gorm.DB
}

// Dialect returns the RDBMS dialect: postgres, mysql, etc
func (rw *GormReadWriter) Dialect() (string, error) {
	if rw.Tx == nil {
		return "", errors.New("create Tx is nil for Dialect")
	}
	return rw.Tx.Dialect().GetName(), nil
}

// DB returns the sql.DB
func (rw *GormReadWriter) DB() (*sql.DB, error) {
	if rw.Tx == nil {
		return nil, errors.New("create Tx is nil for DB")
	}
	return rw.Tx.DB(), nil
}

// gormDB returns a *gorm.DB
func (rw *GormReadWriter) gormDB() (*gorm.DB, error) {
	if rw.Tx == nil {
		return nil, errors.New("create Tx is nil for gormDB")
	}
	dialect, err := rw.Dialect()
	if err != nil {
		return nil, fmt.Errorf("error getting dialect %w for gormDB", err)
	}
	db, err := rw.DB()
	if err != nil {
		return nil, fmt.Errorf("error getting DB %w for gormDB", err)
	}
	return gorm.Open(dialect, db)
}

// CreateConstraint will create a db constraint if it doesn't already exist
func (w *GormReadWriter) CreateConstraint(tableName string, constraintName string, constraint string) error {
	return w.Tx.Exec("create_constraint_if_not_exists(?, ?, ?)", tableName, constraintName, constraint).Error
}

// Create an object in the db with options: WithOplog (which requires WithMetadata, WithWrapper)
func (rw *GormReadWriter) Create(ctx context.Context, i interface{}, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("create Tx is nil")
	}
	opts := GetOpts(opt...)
	withOplog := opts[optionWithOplog].(bool)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if i == nil {
		return errors.New("create interface is nil")
	}
	if vetter, ok := i.(VetForWriter); ok {
		if err := vetter.VetForWrite(); err != nil {
			return fmt.Errorf("error on Create %w", err)
		}
	}
	if err := rw.Tx.Create(i).Error; err != nil {
		return fmt.Errorf("error creating: %w", err)
	}
	if withOplog {
		if opts[optionWithWrapper] == nil {
			return errors.New("error wrapper is nil for create WithWrapper")
		}
		withWrapper, ok := opts[optionWithWrapper].(wrapping.Wrapper)
		if !ok {
			return errors.New("error not a wrapping.Wrapper for create WithWrapper")
		}
		withMetadata := opts[optionWithMetadata].(oplog.Metadata)
		if len(withMetadata) == 0 {
			return errors.New("error no metadata for create WithOplog")
		}
		replayable, ok := i.(oplog.ReplayableMessage)
		if !ok {
			return errors.New("error not a replayable message for create WithOplog")
		}
		gdb, err := rw.gormDB()
		if err != nil {
			return fmt.Errorf("error getting underlying gorm DB %w for create WithOplog", err)
		}
		ticketer, err := oplog.NewGormTicketer(gdb, oplog.WithAggregateNames(true))
		if err != nil {
			return fmt.Errorf("error getting Ticketer %w for create WithOplog", err)
		}
		err = ticketer.InitTicket(replayable.TableName())
		if err != nil {
			return fmt.Errorf("error getting initializing ticket %w for create WithOplog", err)
		}
		ticket, err := ticketer.GetTicket(replayable.TableName())
		if err != nil {
			return fmt.Errorf("error getting ticket %w for create WithOplog", err)
		}

		entry, err := oplog.NewEntry(
			replayable.TableName(),
			withMetadata,
			withWrapper,
			ticketer,
		)

		err = entry.WriteEntryWith(
			ctx,
			&oplog.GormWriter{Tx: gdb},
			ticket,
			&oplog.Message{Message: i.(proto.Message), TypeName: replayable.TableName(), OpType: oplog.OpType_CREATE_OP},
		)
		if err != nil {
			return fmt.Errorf("error creating oplog entry %w for create WithOplog", err)
		}
	}
	return nil
}

// Update an object in the db, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
// it will send every field to the DB.  Update supports embedding a struct (or structPtr) one level deep for updating
func (w *GormReadWriter) Update(ctx context.Context, i interface{}, fieldMaskPaths []string, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("update Tx is nil")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		w.Tx.LogMode(true)
		defer w.Tx.LogMode(false)
	}

	if i == nil {
		return errors.New("update interface is nil")
	}
	if vetter, ok := i.(VetForWriter); ok {
		if err := vetter.VetForWrite(); err != nil {
			return fmt.Errorf("error on Create %w", err)
		}
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
			kind := structTyp.Field(i).Type.Kind()
			if kind == reflect.Struct || kind == reflect.Ptr {
				embType := structTyp.Field(i).Type
				// check if the embedded field is exported via CanInterface()
				if val.Field(i).CanInterface() {
					embVal := reflect.Indirect(reflect.ValueOf(val.Field(i).Interface()))
					// if it's a ptr to a struct, then we need a few more bits before proceeding.
					if kind == reflect.Ptr {
						embVal = val.Field(i).Elem()
						embType = embVal.Type()
						if embType.Kind() != reflect.Struct {
							continue
						}
					}
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
	if len(updateFields) == 0 {
		return fmt.Errorf("error no update fields matched using fieldMaskPaths: %s", fieldMaskPaths)
	}
	if err := w.Tx.Model(i).Updates(updateFields).Error; err != nil {
		return fmt.Errorf("error updating: %w", err)
	}
	return nil
}

// LookupByFriendlyName will lookup resource my its friendly_name which must be unique
func (rw *GormReadWriter) LookupByFriendlyName(ctx context.Context, resource ResourceWithFriendlyName, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("error db nil for LookupByFriendlyName")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByFriendlyName")
	}
	if resource.GetFriendlyName() == "" {
		return errors.New("error friendlyName empty string for LookupByFriendlyName")
	}
	return rw.Tx.Where("friendly_name = ?", resource.GetFriendlyName()).First(resource).Error
}

// LookupByPublicId will lookup resource my its public_id which must be unique
func (rw *GormReadWriter) LookupByPublicId(ctx context.Context, resource ResourceWithPublicId, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("error db nil for LookupByPublicId")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByPublicId")
	}
	if resource.GetPublicId() == "" {
		return errors.New("error publicId empty string for LookupByPublicId")
	}
	return rw.Tx.Where("public_id = ?", resource.GetPublicId()).First(resource).Error
}

// LookupById will lookup resource my its internal id which must be unique
func (rw *GormReadWriter) LookupById(ctx context.Context, resource ResourceWithId, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("error db nil for LookupByInternalId")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByInternalId")
	}
	if resource.GetId() == 0 {
		return errors.New("error internalId is 0 for LookupByInternalId")
	}
	return rw.Tx.Where("id = ?", resource.GetId()).First(resource).Error
}

// LookupBy will lookup the first resource using a where clause with parameters (it only returns the first one)
func (rw *GormReadWriter) LookupBy(ctx context.Context, resource interface{}, where string, args ...interface{}) error {
	if rw.Tx == nil {
		return errors.New("error db nil for SearchBy")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupBy")
	}
	return rw.Tx.Where(where, args...).First(resource).Error
}

// SearchBy will search for all the resources it can find using a where clause with parameters
func (rw *GormReadWriter) SearchBy(ctx context.Context, resources interface{}, where string, args ...interface{}) error {
	if rw.Tx == nil {
		return errors.New("error db nil for SearchBy")
	}
	if reflect.ValueOf(resources).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for SearchBy")
	}
	return rw.Tx.Where(where, args...).Find(resources).Error
}
