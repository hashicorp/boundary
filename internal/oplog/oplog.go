// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"bytes"
	"context"
	"fmt"
	"io"
	reflect "reflect"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

// Version of oplog entries (among other things, it's used to manage upgrade
// compatibility when replicating)
//
//	v1: initial version
//	v2: adds the new Message.Opts
const Version = "v2"

// Message wraps a proto.Message with some other bits like operation type,
// paths and options.
type Message struct {
	proto.Message
	TypeName       string
	OpType         OpType
	FieldMaskPaths []string
	SetToNullPaths []string
	Opts           []dbw.Option
}

// Entry represents an oplog entry
type Entry struct {
	*store.Entry
	Wrapper  wrapping.Wrapper `gorm:"-"`
	Ticketer Ticketer         `gorm:"-"`
}

// Metadata provides meta information about the Entry
type Metadata map[string][]string

// NewEntry creates a new Entry
func NewEntry(ctx context.Context, aggregateName string, metadata Metadata, wrapper wrapping.Wrapper, ticketer Ticketer) (*Entry, error) {
	const op = "oplog.NewEntry"
	if util.IsNil(wrapper) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil wrapper")
	}
	keyId, err := wrapper.KeyId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	entry := Entry{
		Entry: &store.Entry{
			AggregateName: aggregateName,
			Version:       Version,
			KeyId:         keyId,
		},
		Wrapper:  wrapper,
		Ticketer: ticketer,
	}
	if len(metadata) > 0 {
		storeMD := []*store.Metadata{}
		for k, v := range metadata {
			if len(v) > 0 {
				for _, vv := range v {
					storeMD = append(storeMD, &store.Metadata{Key: k, Value: vv})
				}
				continue
			}
			// this metadata just has a key with no values
			storeMD = append(storeMD, &store.Metadata{Key: k})
		}
		entry.Metadata = storeMD
	}
	if err := entry.validate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &entry, nil
}

func (e *Entry) validate(ctx context.Context) error {
	const op = "oplog.(Entry).validate"
	if util.IsNil(e.Wrapper) {
		return errors.New(ctx, errors.InvalidParameter, op, "nil wrapper")
	}
	if util.IsNil(e.Ticketer) {
		return errors.New(ctx, errors.InvalidParameter, op, "nil ticketer")
	}
	if e.Entry == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil entry")
	}
	if e.Entry.Version == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing entry version")
	}
	if e.Entry.AggregateName == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing entry aggregate name")
	}
	if e.Entry.KeyId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing entry key id")
	}
	return nil
}

// UnmarshalData the data attribute from []byte (treated as a FIFO QueueBuffer) to a []proto.Message
func (e *Entry) UnmarshalData(ctx context.Context, types *TypeCatalog) ([]Message, error) {
	const op = "oplog.(Entry).UnmarshalData"
	if types == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil type catalog")
	}
	if len(e.Data) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing data")
	}
	msgs := []Message{}
	queue := Queue{
		Buffer:  *bytes.NewBuffer(e.Data),
		Catalog: types,
	}
	for {
		item, err := queue.remove(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error removing item from queue"))
		}
		name, err := types.GetTypeName(ctx, item.msg)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		dbwOpts, err := convertToDbwOpts(ctx, item.operationOptions)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		msgs = append(msgs, Message{
			Message:        item.msg,
			TypeName:       name,
			OpType:         item.opType,
			FieldMaskPaths: item.fieldMask,
			SetToNullPaths: item.setToNullPaths,
			Opts:           dbwOpts,
		})
	}
	return msgs, nil
}

func convertToDbwOpts(ctx context.Context, opts *OperationOptions) ([]dbw.Option, error) {
	const op = "oplog.convertToDbwOpts"
	if opts == nil {
		return []dbw.Option{}, nil
	}
	dbwOpts := []dbw.Option{
		dbw.WithSkipVetForWrite(opts.GetWithSkipVetForWrite()),
	}
	if opts.GetWithVersion() != nil {
		dbwOpts = append(dbwOpts, dbw.WithVersion(&opts.GetWithVersion().Value))
	}
	if opts.GetWithOnConflict() != nil {
		c := &dbw.OnConflict{}

		switch targetType := opts.GetWithOnConflict().GetTarget().(type) {
		case *WithOnConflict_Columns:
			c.Target = dbw.Columns(opts.GetWithOnConflict().GetColumns().GetNames())
		case *WithOnConflict_Constraint:
			c.Target = dbw.Constraint(opts.GetWithOnConflict().GetConstraint())
		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("not a supported target type: %T", targetType))
		}

		switch actionType := opts.GetWithOnConflict().GetAction().(type) {
		case *WithOnConflict_DoNothing:
			c.Action = dbw.DoNothing(opts.GetWithOnConflict().GetDoNothing())
		case *WithOnConflict_UpdateAll:
			c.Action = dbw.UpdateAll(opts.GetWithOnConflict().GetUpdateAll())
		case *WithOnConflict_ColumnValues:
			cvAction := make([]dbw.ColumnValue, 0, len(actionType.ColumnValues.GetValues()))
			for _, cv := range actionType.ColumnValues.GetValues() {
				newColVal := dbw.ColumnValue{
					Column: cv.GetName(),
				}
				switch pbVal := cv.Value.(type) {
				case *ColumnValue_Raw:
					newColVal.Value = pbVal.Raw.AsInterface()
				case *ColumnValue_ExprValue:
					expr := dbw.ExprValue{
						Sql: pbVal.ExprValue.GetSql(),
					}
					args := make([]any, 0, len(pbVal.ExprValue.GetArgs()))
					for _, a := range pbVal.ExprValue.GetArgs() {
						args = append(args, a.AsInterface())
					}
					if len(args) > 0 {
						expr.Vars = args
					}
					newColVal.Value = expr
				case *ColumnValue_Column:
					newColVal.Value = dbw.Column{
						Name:  pbVal.Column.GetName(),
						Table: pbVal.Column.GetTable(),
					}
				default:
					return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("not a supported column value type: %T", pbVal))
				}
				cvAction = append(cvAction, newColVal)
			}
			c.Action = cvAction
		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("not a supported action type: %T", actionType))
		}
		dbwOpts = append(dbwOpts, dbw.WithOnConflict(c))
	}
	if opts.GetWithWhereClause() != "" {
		sql := opts.GetWithWhereClause()
		args := make([]any, 0, len(opts.GetWithWhereClauseArgs()))
		for _, a := range opts.GetWithWhereClauseArgs() {
			args = append(args, a.AsInterface())
		}
		dbwOpts = append(dbwOpts, dbw.WithWhere(sql, args...))

	}
	return dbwOpts, nil
}

// convertFromDbwOpts converts dbw options to an OperationalOptions for an Entry
func convertFromDbwOpts(ctx context.Context, opts dbw.Options) (*OperationOptions, error) {
	const op = "oplog.convertFromDbwOptions"
	pbOpts := &OperationOptions{
		WithSkipVetForWrite: opts.WithSkipVetForWrite,
		WithWhereClause:     opts.WithWhereClause,
	}
	if opts.WithVersion != nil {
		pbOpts.WithVersion = &wrappers.UInt32Value{Value: *opts.WithVersion}
	}

	clauseValues := make([]*structpb.Value, 0, len(opts.WithWhereClauseArgs))
	for _, arg := range opts.WithWhereClauseArgs {
		v, err := structpb.NewValue(arg)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		clauseValues = append(clauseValues, v)
	}
	pbOpts.WithWhereClauseArgs = clauseValues

	if opts.WithOnConflict != nil {
		c := &WithOnConflict{}
		switch target := opts.WithOnConflict.Target.(type) {
		case dbw.Constraint:
			c.Target = &WithOnConflict_Constraint{string(target)}
		case dbw.Columns:
			c.Target = &WithOnConflict_Columns{
				&Columns{
					Names: []string(target),
				},
			}
		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("not a supported target type: %T", target))
		}
		switch action := opts.WithOnConflict.Action.(type) {
		case dbw.DoNothing:
			c.Action = &WithOnConflict_DoNothing{bool(action)}
		case dbw.UpdateAll:
			c.Action = &WithOnConflict_UpdateAll{bool(action)}
		case []dbw.ColumnValue:
			colVals := make([]*ColumnValue, 0, len(action))
			for _, cv := range action {
				pbColVal := &ColumnValue{
					Name: cv.Column,
				}
				switch cvVal := cv.Value.(type) {
				case dbw.ExprValue:
					args := make([]*structpb.Value, 0, len(cvVal.Vars))
					for _, vv := range cvVal.Vars {
						pbVar, err := structpb.NewValue(vv)
						if err != nil {
							return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create expr arg"))
						}
						args = append(args, pbVar)
					}
					pbColVal.Value = &ColumnValue_ExprValue{&ExprValue{
						Sql:  cvVal.Sql,
						Args: args,
					}}
				case dbw.Column:
					pbColVal.Value = &ColumnValue_Column{
						&Column{
							Name:  cvVal.Name,
							Table: cvVal.Table,
						},
					}
				default:
					exprVal, err := structpb.NewValue(cv.Value)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create column value"))
					}
					pbColVal.Value = &ColumnValue_Raw{exprVal}
				}
				colVals = append(colVals, pbColVal)
			}
			c.Action = &WithOnConflict_ColumnValues{ColumnValues: &ColumnValues{Values: colVals}}
		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("not a valid supported action: %T", action))
		}

		pbOpts.WithOnConflict = c
	}
	return pbOpts, nil
}

// WriteEntryWith the []proto.Message marshaled into the entry data as a FIFO QueueBuffer
// if Wrapper != nil then the data is authentication encrypted
func (e *Entry) WriteEntryWith(ctx context.Context, tx *Writer, ticket *store.Ticket, msgs ...*Message) error {
	const op = "oplog.(Entry).WriteEntryWith"
	if tx == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if err := e.validate(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if ticket == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil ticket")
	}
	if ticket.Version == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ticket version")
	}
	queue := Queue{}
	for _, m := range msgs {
		if m == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "nil message")
		}
		if err := queue.add(ctx, m.Message, m.TypeName, m.OpType, WithOperationOptions(m.Opts...), WithFieldMaskPaths(m.FieldMaskPaths), WithSetToNullPaths(m.SetToNullPaths)); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("error adding message to queue"))
		}
	}
	e.Data = append(e.Data, queue.Bytes()...)

	if e.Wrapper != nil {
		if err := e.encryptData(ctx); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	rw := dbw.New(tx.DB)
	if err := rw.Create(ctx, e); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error writing data to storage"))
	}
	if err := e.Ticketer.Redeem(ctx, ticket); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// Write the entry as is with whatever it has for e.Data marshaled into a FIFO QueueBuffer
// If Wrapper != nil then the data is authentication encrypted
func (e *Entry) Write(ctx context.Context, tx *Writer, ticket *store.Ticket) error {
	const op = "oplog.(Entry).Write"
	if err := e.validate(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if ticket == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil ticket")
	}
	if ticket.Version == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ticket version")
	}
	if e.Wrapper != nil {
		if err := e.encryptData(ctx); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	rw := dbw.New(tx.DB)
	if err := rw.Create(ctx, e); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error writing data to storage"))
	}
	if err := e.Ticketer.Redeem(ctx, ticket); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// encryptData the entry's data using its Wrapper (wrapping.Wrapper)
func (e *Entry) encryptData(ctx context.Context) error {
	const op = "oplog.(Entry).EncryptData"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, e.Wrapper, e.Entry, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// DecryptData will decrypt the entry's data using its Wrapper (wrapping.Wrapper)
func (e *Entry) DecryptData(ctx context.Context) error {
	const op = "oplog.(Entry).DecryptData"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.UnwrapStruct(ctx, e.Wrapper, e.Entry, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

// Replay provides the ability to replay an entry.  you must initialize any new tables ending with the tableSuffix before
// calling Replay, otherwise you'll get "a table doesn't exist" error.
func (e *Entry) Replay(ctx context.Context, tx *Writer, types *TypeCatalog, tableSuffix string) error {
	const op = "oplog.(Entry).Replay"
	msgs, err := e.UnmarshalData(ctx, types)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, m := range msgs {
		em, ok := m.Message.(ReplayableMessage)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%T is not a replayable message", m.Message))
		}
		origTableName := em.TableName()
		defer em.SetTableName(origTableName)

		/*
			how replay will be implemented for snapshots is still very much under discussion.
			when we go to implement snapshots we may very well need to refactor
			this create table choice... there are many issues with doing the
			"create" in this manner:
				* the perms needed to create a table and possible security issues
				* the fk references would be to the original tables, not the new
				  replay tables.
				* we need a way to create a replay table that contains the existing
				  named constraints.  Currently, on conflicts using a constraint
				  target won't work.
			It may be a better choice to just create separate schemas for replay
			named blue and green since we need at min of two replay tables
			definitions. if we went with separate schemas they could be create
			with a boundary cli cmd that had appropriate privs (reducing
			security issues) and the separate schemas wouldn't have the fk
			reference issues mentioned above.


		*/
		replayTable := origTableName + tableSuffix
		hasTable, err := tx.hasTable(ctx, replayTable)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if !hasTable {
			if err := tx.createTableLike(ctx, origTableName, replayTable); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
		rw := dbw.New(tx.DB)

		m.Opts = append(m.Opts, dbw.WithTable(replayTable))
		switch m.OpType {
		case OpType_OP_TYPE_CREATE:
			if err := rw.Create(ctx, m.Message, m.Opts...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		case OpType_OP_TYPE_CREATE_ITEMS:
			// TODO: jimlambrt 12/2021 -> while this will work for
			// CreateItems(...) it's hardly efficient.  We'll need to refactor
			// oplog quite a bit to support a multi-message operation.
			if err := rw.CreateItems(ctx, convertToSlice(m.Message), m.Opts...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		case OpType_OP_TYPE_UPDATE:
			if _, err := rw.Update(ctx, m.Message, m.FieldMaskPaths, m.SetToNullPaths, m.Opts...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		case OpType_OP_TYPE_DELETE:
			if _, err := rw.Delete(ctx, m.Message, m.Opts...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		case OpType_OP_TYPE_DELETE_ITEMS:
			// TODO: jimlambrt 12/2021 -> while this will work for
			// DeleteItems(...) it's hardly efficient.  We'll need to refactor
			// oplog quite a bit to support a multi-message operation.
			if _, err := rw.DeleteItems(ctx, convertToSlice(m.Message), m.Opts...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid operation %T", m.OpType))
		}
	}
	return nil
}

func convertToSlice(m protoreflect.ProtoMessage) any {
	valueType := reflect.TypeOf(m) // Assume all values are the same type
	sliceType := reflect.SliceOf(valueType)
	sliceValue := reflect.MakeSlice(sliceType, 1, 1)
	sliceValue.Index(0).Set(reflect.ValueOf(m))
	return sliceValue.Interface()
}
