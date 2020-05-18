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

var (
	// ErrRecordNotFound returns a "record not found" error and it only occurs
	// when attempting to read from the database into struct.
	// When reading into a slice it won't return this error.
	ErrRecordNotFound = errors.New("record not found")
)

const NoRowsAffected = 0

// Reader interface defines lookups/searching for resources
type Reader interface {
	// LookupByName will lookup resource by its friendly name which must be unique
	LookupByName(ctx context.Context, resource ResourceNamer, opt ...Option) error

	// LookupByPublicId will lookup resource by its public_id which must be unique
	LookupByPublicId(ctx context.Context, resource ResourcePublicIder, opt ...Option) error

	// LookupWhere will lookup and return the first resource using a where clause with parameters
	LookupWhere(ctx context.Context, resource interface{}, where string, args ...interface{}) error

	// SearchWhere will search for all the resources it can find using a where clause with parameters
	SearchWhere(ctx context.Context, resources interface{}, where string, args ...interface{}) error

	// ScanRows will scan sql rows into the interface provided
	ScanRows(rows *sql.Rows, result interface{}) error

	// DB returns the sql.DB
	DB() (*sql.DB, error)
}

// Writer interface defines create, update and retryable transaction handlers
type Writer interface {
	// DoTx will wrap the TxHandler in a retryable transaction
	DoTx(ctx context.Context, retries uint, backOff Backoff, Handler TxHandler) (RetryInfo, error)

	// Update an object in the db, if there's a fieldMask then only the
	// field_mask.proto paths are updated, otherwise it will send every field to
	// the DB.  options: WithOplog the caller is responsible for the transaction
	// life cycle of the writer and if an error is returned the caller must
	// decide what to do with the transaction, which almost always should be to
	// rollback.  Update returns the number of rows updated or an error.
	Update(ctx context.Context, i interface{}, fieldMaskPaths []string, opt ...Option) (int, error)

	// Create an object in the db with options: WithOplog
	// the caller is responsible for the transaction life cycle of the writer
	// and if an error is returned the caller must decide what to do with
	// the transaction, which almost always should be to rollback.
	Create(ctx context.Context, i interface{}, opt ...Option) error

	// Delete an object in the db with options: WithOplog
	// the caller is responsible for the transaction life cycle of the writer
	// and if an error is returned the caller must decide what to do with
	// the transaction, which almost always should be to rollback. Delete
	// returns the number of rows deleted or an error.
	Delete(ctx context.Context, i interface{}, opt ...Option) (int, error)

	// DB returns the sql.DB
	DB() (*sql.DB, error)
}

const (
	StdRetryCnt = 20
)

// RetryInfo provides information on the retries of a transaction
type RetryInfo struct {
	Retries int
	Backoff time.Duration
}

// TxHandler defines a handler for a func that writes a transaction for use with DoTx
type TxHandler func(Writer) error

// ResourcePublicIder defines an interface that LookupByPublicId() can use to get the resource's public id
type ResourcePublicIder interface {
	GetPublicId() string
}

// ResourceNamer defines an interface that LookupByName() can use to get the resource's friendly name
type ResourceNamer interface {
	GetName() string
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
	VetForWrite(ctx context.Context, r Reader, opType OpType, opt ...Option) error
}

// Db uses a gorm DB connection for read/write
type Db struct {
	underlying *gorm.DB
}

// ensure that Db implements the interfaces of: Reader and Writer
var _ Reader = (*Db)(nil)
var _ Writer = (*Db)(nil)

func New(underlying *gorm.DB) *Db {
	return &Db{underlying: underlying}
}

// DB returns the sql.DB
func (rw *Db) DB() (*sql.DB, error) {
	if rw.underlying == nil {
		return nil, errors.New("underlying db is nil")
	}
	return rw.underlying.DB(), nil
}

// Scan rows will scan the rows into the interface
func (rw *Db) ScanRows(rows *sql.Rows, result interface{}) error {
	return rw.underlying.ScanRows(rows, result)
}

var ErrNotResourceWithId = errors.New("not a resource with an id")

func (rw *Db) lookupAfterWrite(ctx context.Context, i interface{}, opt ...Option) error {
	opts := GetOpts(opt...)
	withLookup := opts.withLookup

	if !withLookup {
		return nil
	}
	if _, ok := i.(ResourcePublicIder); ok {
		if err := rw.LookupByPublicId(ctx, i.(ResourcePublicIder), opt...); err != nil {
			return err
		}
		return nil
	}
	return ErrNotResourceWithId
}

// Create an object in the db with options: WithOplog and WithLookup (to force a lookup after create))
func (rw *Db) Create(ctx context.Context, i interface{}, opt ...Option) error {
	if rw.underlying == nil {
		return errors.New("create underlying db is nil")
	}
	opts := GetOpts(opt...)
	withOplog := opts.withOplog
	withDebug := opts.withDebug
	if withOplog {
		// let's validate oplog options before we start writing to the database
		_, err := validateOplogArgs(i, opts)
		if err != nil {
			return err
		}
	}
	if withDebug {
		rw.underlying.LogMode(true)
		defer rw.underlying.LogMode(false)
	}
	if i == nil {
		return errors.New("create interface is nil")
	}
	if vetter, ok := i.(VetForWriter); ok {
		if err := vetter.VetForWrite(ctx, rw, CreateOp); err != nil {
			return fmt.Errorf("error on create %w", err)
		}
	}
	if err := rw.underlying.Create(i).Error; err != nil {
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

// Update an object in the db, if there's a fieldMask then only the
// field_mask.proto paths are updated, otherwise it will send every field to the
// DB.  Update supports embedding a struct (or structPtr) one level deep for
// updating. Update returns the number of rows updated and any errors.
func (rw *Db) Update(ctx context.Context, i interface{}, fieldMaskPaths []string, opt ...Option) (int, error) {
	if rw.underlying == nil {
		return NoRowsAffected, errors.New("update underlying db is nil")
	}
	opts := GetOpts(opt...)
	withDebug := opts.withDebug
	withOplog := opts.withOplog
	if withOplog {
		// let's validate oplog options before we start writing to the database
		_, err := validateOplogArgs(i, opts)
		if err != nil {
			return NoRowsAffected, err
		}
	}
	if withDebug {
		rw.underlying.LogMode(true)
		defer rw.underlying.LogMode(false)
	}
	if i == nil {
		return NoRowsAffected, errors.New("update interface is nil")
	}
	if vetter, ok := i.(VetForWriter); ok {
		if err := vetter.VetForWrite(ctx, rw, UpdateOp, WithFieldMaskPaths(fieldMaskPaths)); err != nil {
			return NoRowsAffected, fmt.Errorf("error on update %w", err)
		}
	}
	if len(fieldMaskPaths) == 0 {
		if err := rw.underlying.Save(i).Error; err != nil {
			return NoRowsAffected, fmt.Errorf("error updating: %w", err)
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
		return NoRowsAffected, fmt.Errorf("error no update fields matched using fieldMaskPaths: %s", fieldMaskPaths)
	}
	underlying := rw.underlying.Model(i).Updates(updateFields)
	if underlying.Error != nil {
		return NoRowsAffected, fmt.Errorf("error updating: %w", underlying.Error)
	}
	rowsUpdated := int(underlying.RowsAffected)
	if withOplog && rowsUpdated > 0 {
		if err := rw.addOplog(ctx, UpdateOp, opts, i); err != nil {
			return rowsUpdated, err
		}
	}
	// we need to force a lookupAfterWrite so the resource returned is correctly initialized
	// from the db
	opt = append(opt, WithLookup(true))
	if err := rw.lookupAfterWrite(ctx, i, opt...); err != nil {
		return NoRowsAffected, fmt.Errorf("lookup error after update: %w", err)
	}
	return rowsUpdated, nil
}

// Delete an object in the db with options: WithOplog (which requires
// WithMetadata, WithWrapper). Delete returns the number of rows deleted and
// any errors.
func (rw *Db) Delete(ctx context.Context, i interface{}, opt ...Option) (int, error) {
	if rw.underlying == nil {
		return NoRowsAffected, errors.New("delete underlying db is nil")
	}
	if i == nil {
		return NoRowsAffected, errors.New("delete interface is nil")
	}
	opts := GetOpts(opt...)
	withDebug := opts.withDebug
	withOplog := opts.withOplog
	if withOplog {
		_, err := validateOplogArgs(i, opts)
		if err != nil {
			return NoRowsAffected, err
		}
	}
	if withDebug {
		rw.underlying.LogMode(true)
		defer rw.underlying.LogMode(false)
	}
	underlying := rw.underlying.Delete(i)
	if underlying.Error != nil {
		return NoRowsAffected, fmt.Errorf("error deleting: %w", underlying.Error)
	}
	rowsDeleted := int(underlying.RowsAffected)
	if withOplog && rowsDeleted > 0 {
		if err := rw.addOplog(ctx, DeleteOp, opts, i); err != nil {
			return rowsDeleted, err
		}
	}
	return rowsDeleted, nil
}

func validateOplogArgs(i interface{}, opts Options) (oplog.ReplayableMessage, error) {
	oplogArgs := opts.oplogOpts
	if oplogArgs.wrapper == nil {
		return nil, errors.New("error no wrapper WithOplog")
	}
	if len(oplogArgs.metadata) == 0 {
		return nil, errors.New("error no metadata for WithOplog")
	}
	replayable, ok := i.(oplog.ReplayableMessage)
	if !ok {
		return nil, errors.New("error not a replayable message for WithOplog")
	}
	return replayable, nil
}

func (rw *Db) addOplog(ctx context.Context, opType OpType, opts Options, i interface{}) error {
	oplogArgs := opts.oplogOpts
	replayable, err := validateOplogArgs(i, opts)
	if err != nil {
		return err
	}
	gdb := rw.underlying
	withDebug := opts.withDebug
	if withDebug {
		gdb.LogMode(true)
		defer gdb.LogMode(false)
	}
	ticketer, err := oplog.NewGormTicketer(gdb, oplog.WithAggregateNames(true))
	if err != nil {
		return fmt.Errorf("error getting Ticketer %w for WithOplog", err)
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
func (w *Db) DoTx(ctx context.Context, retries uint, backOff Backoff, Handler TxHandler) (RetryInfo, error) {
	if w.underlying == nil {
		return RetryInfo{}, errors.New("do underlying db is nil")
	}
	info := RetryInfo{}
	for attempts := uint(1); ; attempts++ {
		if attempts > retries+1 {
			return info, fmt.Errorf("Too many retries: %d of %d", attempts-1, retries+1)
		}

		// step one of this, start a transaction...
		newTx := w.underlying.BeginTx(ctx, nil)

		if err := Handler(&Db{newTx}); err != nil {
			if err := newTx.Rollback().Error; err != nil {
				return info, err
			}
			if errors.Is(err, oplog.ErrTicketAlreadyRedeemed) {
				d := backOff.Duration(attempts)
				info.Retries++
				info.Backoff = info.Backoff + d
				time.Sleep(d)
				continue
			}
			return info, err
		}

		if err := newTx.Commit().Error; err != nil {
			if err := newTx.Rollback().Error; err != nil {
				return info, err
			}
			return info, err
		}
		return info, nil // it all worked!!!
	}
}

// LookupByName will lookup resource my its friendly name which must be unique
func (rw *Db) LookupByName(ctx context.Context, resource ResourceNamer, opt ...Option) error {
	if rw.underlying == nil {
		return errors.New("error underlying db nil for lookup by name")
	}
	opts := GetOpts(opt...)
	withDebug := opts.withDebug
	if withDebug {
		rw.underlying.LogMode(true)
		defer rw.underlying.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for lookup by name")
	}
	if resource.GetName() == "" {
		return errors.New("error name empty string for lookup by name")
	}
	if err := rw.underlying.Where("name = ?", resource.GetName()).First(resource).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrRecordNotFound
		}
		return err
	}
	return nil
}

// LookupByPublicId will lookup resource my its public_id which must be unique
func (rw *Db) LookupByPublicId(ctx context.Context, resource ResourcePublicIder, opt ...Option) error {
	if rw.underlying == nil {
		return errors.New("error underlying db nil for lookup by public id")
	}
	opts := GetOpts(opt...)
	withDebug := opts.withDebug
	if withDebug {
		rw.underlying.LogMode(true)
		defer rw.underlying.LogMode(false)
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for lookup by public id")
	}
	if resource.GetPublicId() == "" {
		return errors.New("error public id empty string for lookup by public id")
	}
	if err := rw.underlying.Where("public_id = ?", resource.GetPublicId()).First(resource).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrRecordNotFound
		}
		return err
	}
	return nil
}

// LookupWhere will lookup the first resource using a where clause with parameters (it only returns the first one)
func (rw *Db) LookupWhere(ctx context.Context, resource interface{}, where string, args ...interface{}) error {
	if rw.underlying == nil {
		return errors.New("error underlying db nil for lookup by")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for lookup by")
	}
	if err := rw.underlying.Where(where, args...).First(resource).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrRecordNotFound
		}
		return err
	}
	return nil
}

// SearchWhere will search for all the resources it can find using a where clause with parameters
func (rw *Db) SearchWhere(ctx context.Context, resources interface{}, where string, args ...interface{}) error {
	if rw.underlying == nil {
		return errors.New("error underlying db nil for search by")
	}
	if reflect.ValueOf(resources).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for search by")
	}
	return rw.underlying.Where(where, args...).Find(resources).Error
}
