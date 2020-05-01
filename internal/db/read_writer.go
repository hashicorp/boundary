package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/jinzhu/gorm"
	"google.golang.org/protobuf/proto"
)

// Reader interface defines lookups/searching for resources
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

	// ScanRows will scan sql rows into the interface provided
	ScanRows(rows *sql.Rows, result interface{}) error

	// DB returns the sql.DB
	DB() (*sql.DB, error)

	// Dialect returns the RDBMS dialect: postgres, mysql, etc
	Dialect() (string, error)
}

// Writer interface defines create, update and retryable transaction handlers
type Writer interface {
	// DoTx will wrap the TxHandler in a retryable transaction
	DoTx(ctx context.Context, retries uint, backOff Backoff, Handler TxHandler) (RetryInfo, error)

	// Update an object in the db, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
	// it will send every field to the DB.  options: WithOplog
	Update(ctx context.Context, i interface{}, fieldMaskPaths []string, opt ...Option) error

	// Create an object in the db with options: WithOplog
	Create(ctx context.Context, i interface{}, opt ...Option) error

	// Delete an object in the db with options: WithOplog
	Delete(ctx context.Context, i interface{}, opt ...Option) error

	// CreateConstraint will create a db constraint if it doesn't already exist
	CreateConstraint(tableName string, constraintName string, constraint string) error

	// DB returns the sql.DB
	DB() (*sql.DB, error)

	// Dialect returns the RDBMS dialect: postgres, mysql, etc
	Dialect() (string, error)
}

// RetryInfo provides information on the retries of a transaction
type RetryInfo struct {
	Retries int
	Backoff time.Duration
}

// TxHandler defines a handler for a func that writes a transaction for use with DoTx
type TxHandler func(Writer) error

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

type OpType int

const (
	UnknownOp OpType = 0
	CreateOp  OpType = 1
	UpdateOp  OpType = 2
	DeleteOp  OpType = 3
)

// VetForWriter provides an interface that Create and Update can use to vet the resource before sending it to the db
type VetForWriter interface {
	VetForWrite(ctx context.Context, r Reader, opType OpType) error
}

// GormReadWriter uses a gorm DB connection for read/write
type GormReadWriter struct {
	Tx *gorm.DB
}

// ensure that GroupRole implements the interfaces of: Resource, ClonableResource, AssignedRole and db.VetForWriter
var _ Reader = (*GormReadWriter)(nil)
var _ Writer = (*GormReadWriter)(nil)

// Dialect returns the RDBMS dialect: postgres, mysql, etc
func (rw *GormReadWriter) Dialect() (string, error) {
	if rw.Tx == nil {
		return "", errors.New("create tx is nil for dialect")
	}
	return rw.Tx.Dialect().GetName(), nil
}

// DB returns the sql.DB
func (rw *GormReadWriter) DB() (*sql.DB, error) {
	if rw.Tx == nil {
		return nil, errors.New("create tx is nil for db")
	}
	return rw.Tx.DB(), nil
}

// Scan rows will scan the rows into the interface
func (rw *GormReadWriter) ScanRows(rows *sql.Rows, result interface{}) error {
	return rw.Tx.ScanRows(rows, result)
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

var ErrNotResourceWithId = errors.New("not a resource with an id")

func (rw *GormReadWriter) lookupAfterWrite(ctx context.Context, i interface{}, opt ...Option) error {
	opts := GetOpts(opt...)
	withLookup := opts[optionWithLookup].(bool)

	if !withLookup {
		return nil
	}
	if _, ok := i.(ResourceWithId); ok {
		if err := rw.LookupById(ctx, i.(ResourceWithId), opt...); err != nil {
			return err
		}
		return nil
	}
	return ErrNotResourceWithId
}

// Create an object in the db with options: WithOplog and WithLookup (to force a lookup after create))
func (rw *GormReadWriter) Create(ctx context.Context, i interface{}, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("create tx is nil")
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
		if err := vetter.VetForWrite(ctx, rw, CreateOp); err != nil {
			return fmt.Errorf("error on Create %w", err)
		}
	}
	if err := rw.Tx.Create(i).Error; err != nil {
		return fmt.Errorf("error creating: %w", err)
	}
	if withOplog {
		if err := rw.addOplog(ctx, CreateOp, opts, i); err != nil {
			return err
		}
	}
	if err := rw.lookupAfterWrite(ctx, i, opt...); err != nil {
		return fmt.Errorf("lookup error after create: %w", err)
	}
	return nil
}

// Update an object in the db, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
// it will send every field to the DB.  Update supports embedding a struct (or structPtr) one level deep for updating
func (rw *GormReadWriter) Update(ctx context.Context, i interface{}, fieldMaskPaths []string, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("update tx is nil")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	withOplog := opts[optionWithOplog].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if i == nil {
		return errors.New("update interface is nil")
	}
	if vetter, ok := i.(VetForWriter); ok {
		if err := vetter.VetForWrite(ctx, rw, UpdateOp); err != nil {
			return fmt.Errorf("error on Create %w", err)
		}
	}
	if len(fieldMaskPaths) == 0 {
		if err := rw.Tx.Save(i).Error; err != nil {
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
	if err := rw.Tx.Model(i).Updates(updateFields).Error; err != nil {
		return fmt.Errorf("error updating: %w", err)
	}
	if withOplog {
		if err := rw.addOplog(ctx, UpdateOp, opts, i); err != nil {
			return err
		}
	}
	if err := rw.lookupAfterWrite(ctx, i, opt...); err != nil {
		return fmt.Errorf("lookup error after update: %w", err)
	}
	return nil
}

// Delete an object in the db with options: WithOplog (which requires WithMetadata, WithWrapper)
func (rw *GormReadWriter) Delete(ctx context.Context, i interface{}, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("delete tx is nil")
	}
	if i == nil {
		return errors.New("delete interface is nil")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	withOplog := opts[optionWithOplog].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if err := rw.Tx.Delete(i).Error; err != nil {
		return fmt.Errorf("error deleting: %w", err)
	}
	if withOplog {
		if err := rw.addOplog(ctx, DeleteOp, opts, i); err != nil {
			return err
		}
	}
	return nil
}

func (rw *GormReadWriter) addOplog(ctx context.Context, opType OpType, opts Options, i interface{}) error {
	oplogArgs := opts[optionOplogArgs].(oplogArgs)
	if oplogArgs.wrapper == nil {
		return errors.New("error wrapper is nil for WithWrapper")
	}
	if len(oplogArgs.metadata) == 0 {
		return errors.New("error no metadata for WithOplog")
	}
	replayable, ok := i.(oplog.ReplayableMessage)
	if !ok {
		return errors.New("error not a replayable message for WithOplog")
	}
	gdb := rw.Tx
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		gdb.LogMode(true)
		defer gdb.LogMode(false)
	}
	ticketer, err := oplog.NewGormTicketer(gdb, oplog.WithAggregateNames(true))
	if err != nil {
		return fmt.Errorf("error getting Ticketer %w for WithOplog", err)
	}
	err = ticketer.InitTicket(replayable.TableName())
	if err != nil {
		return fmt.Errorf("error getting initializing ticket %w for WithOplog", err)
	}
	ticket, err := ticketer.GetTicket(replayable.TableName())
	if err != nil {
		return fmt.Errorf("error getting ticket %w for WithOplog", err)
	}

	entry, err := oplog.NewEntry(
		replayable.TableName(),
		oplogArgs.metadata,
		oplogArgs.wrapper,
		ticketer,
	)
	var entryOp oplog.OpType
	switch opType {
	case CreateOp:
		entryOp = oplog.OpType_OP_TYPE_CREATE
	case UpdateOp:
		entryOp = oplog.OpType_OP_TYPE_UPDATE
	case DeleteOp:
		entryOp = oplog.OpType_OP_TYPE_DELETE
	default:
		return fmt.Errorf("error operation type %v is not supported", opType)
	}
	err = entry.WriteEntryWith(
		ctx,
		&oplog.GormWriter{Tx: gdb},
		ticket,
		&oplog.Message{Message: i.(proto.Message), TypeName: replayable.TableName(), OpType: entryOp},
	)
	if err != nil {
		return fmt.Errorf("error creating oplog entry %w for WithOplog", err)
	}
	return nil
}

// DoTx will wrap the Handler func passed within a transaction with retries
// you should ensure that any objects written to the db in your TxHandler are retryable, which
// means that the object may be sent to the db several times (retried), so things like the primary key must
// be reset before retry
func (w *GormReadWriter) DoTx(ctx context.Context, retries uint, backOff Backoff, Handler TxHandler) (RetryInfo, error) {
	if w.Tx == nil {
		return RetryInfo{}, errors.New("do tx is nil")
	}
	info := RetryInfo{}
	for attempts := uint(1); ; attempts++ {
		if attempts > retries+1 {
			return info, fmt.Errorf("Too many retries: %d of %d", attempts-1, retries+1)
		}
		newTx := w.Tx.BeginTx(ctx, nil)
		if err := Handler(&GormReadWriter{newTx}); err != nil {
			if errors.Is(err, oplog.ErrTicketAlreadyRedeemed) {
				newTx.Rollback() // need to still handle rollback errors
				d := backOff.Duration(attempts)
				info.Retries++
				info.Backoff = info.Backoff + d
				time.Sleep(d)
				continue
			} else {
				return info, err
			}
		} else {
			if err := newTx.Commit().Error; err != nil {
				if errors.Is(err, oplog.ErrTicketAlreadyRedeemed) {
					d := backOff.Duration(attempts)
					info.Retries++
					info.Backoff = info.Backoff + d
					time.Sleep(d)
					continue
				} else {
					return info, err
				}
			}
			break // it all worked!!!
		}
	}
	return info, nil
}

// LookupByFriendlyName will lookup resource my its friendly_name which must be unique
func (rw *GormReadWriter) LookupByFriendlyName(ctx context.Context, resource ResourceWithFriendlyName, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("error tx nil for lookup by friendly name")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for lookup by friendly name")
	}
	if resource.GetFriendlyName() == "" {
		return errors.New("error friendly name empty string for lookup by friendly name")
	}
	return rw.Tx.Where("friendly_name = ?", resource.GetFriendlyName()).First(resource).Error
}

// LookupByPublicId will lookup resource my its public_id which must be unique
func (rw *GormReadWriter) LookupByPublicId(ctx context.Context, resource ResourceWithPublicId, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("error tx nil for lookup by public id")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for lookup by public id")
	}
	if resource.GetPublicId() == "" {
		return errors.New("error public id empty string for lookup by public id")
	}
	return rw.Tx.Where("public_id = ?", resource.GetPublicId()).First(resource).Error
}

// LookupById will lookup resource my its internal id which must be unique
func (rw *GormReadWriter) LookupById(ctx context.Context, resource ResourceWithId, opt ...Option) error {
	if rw.Tx == nil {
		return errors.New("error tx nil for lookup by internal id")
	}
	opts := GetOpts(opt...)
	withDebug := opts[optionWithDebug].(bool)
	if withDebug {
		rw.Tx.LogMode(true)
		defer rw.Tx.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for lookup by internal id")
	}
	if resource.GetId() == 0 {
		return errors.New("error internal id is 0 for lookup by internal id")
	}
	return rw.Tx.Where("id = ?", resource.GetId()).First(resource).Error
}

// LookupBy will lookup the first resource using a where clause with parameters (it only returns the first one)
func (rw *GormReadWriter) LookupBy(ctx context.Context, resource interface{}, where string, args ...interface{}) error {
	if rw.Tx == nil {
		return errors.New("error tx nil for lookup by")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for lookup by")
	}
	return rw.Tx.Where(where, args...).First(resource).Error
}

// SearchBy will search for all the resources it can find using a where clause with parameters
func (rw *GormReadWriter) SearchBy(ctx context.Context, resources interface{}, where string, args ...interface{}) error {
	if rw.Tx == nil {
		return errors.New("error tx nil for search by")
	}
	if reflect.ValueOf(resources).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for search by")
	}
	return rw.Tx.Where(where, args...).Find(resources).Error
}
