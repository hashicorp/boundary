// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

type (
	beforeWriteFn func(any) error
	afterWriteFn  func(any, int) error
)

func (rw *Db) generateOplogBeforeAfterOpts(ctx context.Context, i any, opType OpType, opts Options) (beforeWriteFn, afterWriteFn, error) {
	const op = "db.generateOplogBeforeAfterOpts"
	withOplog := opts.withOplog
	if !withOplog && opts.newOplogMsg == nil && opts.newOplogMsgs == nil {
		return nil, nil, nil // nothing to do, so we're done
	}
	if withOplog && opts.newOplogMsg != nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "both WithOplog and NewOplogMsg options have been specified")
	}
	if opts.withOplog && opts.newOplogMsgs != nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "both WithOplog and NewOplogMsgs options have been specified")
	}
	if opts.newOplogMsg != nil && opts.newOplogMsgs != nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "both NewOplogMsg and NewOplogMsgs (plural) options have been specified")
	}

	var isSlice bool
	var items []any
	rv := reflect.ValueOf(i)
	if isSlice = rv.Kind() == reflect.Slice; isSlice {
		for i := 0; i < rv.Len(); i++ {
			items = append(items, rv.Index(i).Interface())
		}
	}
	if isSlice {
		switch opType {
		case CreateOp, DeleteOp, UpdateOp:
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "Cannot use a slice on a single item operation")
		}
	}

	// let's validate oplog options before we start writing to the database
	switch {
	case isSlice && withOplog:
		if _, err := validateOplogArgs(ctx, items[0], opts); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("oplog validation failed"))
		}
	case withOplog:
		if _, err := validateOplogArgs(ctx, i, opts); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("oplog validation failed"))
		}
	}

	var onConflictDoNothing bool
	if opts.withOnConflict != nil {
		switch opts.withOnConflict.Action.(type) {
		case dbw.DoNothing:
			onConflictDoNothing = true
		}
	}

	var beforeFn beforeWriteFn
	var afterFn afterWriteFn

	var ticket *store.Ticket
	if opts.withOplog {
		beforeFn = func(any) error {
			const op = "db.beforeFn"
			var err error
			switch isSlice {
			case true:
				ticket, err = rw.GetTicket(ctx, items[0])
			default:
				ticket, err = rw.GetTicket(ctx, i)
			}
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			return nil
		}
	}
	switch {
	case withOplog && (opType == CreateOp || opType == UpdateOp || opType == DeleteOp):
		afterFn = func(i any, rowsAffected int) error {
			const op = "db.afterFnSingleItem"
			switch {
			case onConflictDoNothing && rowsAffected == 0:
			default:
				if err := rw.addOplog(ctx, CreateOp, opts, ticket, i); err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}
			return nil
		}
	case withOplog && (opType == CreateItemsOp || opType == DeleteItemsOp):
		afterFn = func(i any, rowsAffected int) error {
			const op = "db.afterFnMultiItem"
			err := rw.addOplogForItems(ctx, opType, opts, ticket, items)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("returning oplog msgs failed"))
			}
			return nil
		}
	case opts.newOplogMsg != nil:
		if isSlice {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "new oplog msg (singular) is not a supported option")
		}
		afterFn = func(i any, rowsAffected int) error {
			const op = "db.afterFnNewOplogMsg"
			switch {
			case onConflictDoNothing && rowsAffected == 0:
			default:
				msg, err := rw.newOplogMessage(ctx, CreateOp, i)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("returning oplog failed"))
				}
				*opts.newOplogMsg = *msg
			}
			return nil
		}

	case opts.newOplogMsgs != nil:
		afterFn = func(i any, rowsAffected int) error {
			const op = "db.afterFnNewOplogMsgs"
			if rowsAffected > 0 {
				msgs, err := rw.oplogMsgsForItems(ctx, CreateOp, opts, items)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("returning oplog msgs failed"))
				}
				*opts.newOplogMsgs = append(*opts.newOplogMsgs, msgs...)
			}
			return nil
		}
	}
	return beforeFn, afterFn, nil
}

func validateOplogArgs(ctx context.Context, i any, opts Options) (oplog.ReplayableMessage, error) {
	const op = "db.validateOplogArgs"
	oplogArgs := opts.oplogOpts
	if oplogArgs.wrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing wrapper", errors.WithoutEvent())
	}
	if len(oplogArgs.metadata) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing metadata", errors.WithoutEvent())
	}
	replayable, ok := i.(oplog.ReplayableMessage)
	if !ok {
		return nil, errors.E(ctx, errors.WithOp(op), errors.WithMsg("not a replayable message"), errors.WithoutEvent())
	}
	return replayable, nil
}

func (rw *Db) getTicketFor(ctx context.Context, aggregateName string) (*store.Ticket, error) {
	const op = "db.getTicketFor"
	if rw.underlying == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s: underlying db missing", aggregateName), errors.WithoutEvent())
	}
	ticketer, err := oplog.NewTicketer(ctx, rw.UnderlyingDB()(), oplog.WithAggregateNames(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("%s: unable to get Ticketer", aggregateName)), errors.WithoutEvent())
	}
	ticket, err := ticketer.GetTicket(ctx, aggregateName)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("%s: unable to get ticket", aggregateName)), errors.WithoutEvent())
	}
	return ticket, nil
}

// GetTicket returns an oplog ticket for the aggregate root of "i" which can
// be used to WriteOplogEntryWith for that aggregate root.
func (rw *Db) GetTicket(ctx context.Context, i any) (*store.Ticket, error) {
	const op = "db.GetTicket"
	if rw.underlying == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing underlying db", errors.WithoutEvent())
	}
	if isNil(i) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing interface", errors.WithoutEvent())
	}
	replayable, ok := i.(oplog.ReplayableMessage)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "not a replayable message", errors.WithoutEvent())
	}
	return rw.getTicketFor(ctx, replayable.TableName())
}

func (rw *Db) oplogMsgsForItems(ctx context.Context, opType OpType, opts Options, items []any) ([]*oplog.Message, error) {
	const op = "db.oplogMsgsForItems"
	if len(items) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing items", errors.WithoutEvent())
	}
	oplogMsgs := []*oplog.Message{}
	var foundType reflect.Type
	for i, item := range items {
		if i == 0 {
			foundType = reflect.TypeOf(item)
		}
		currentType := reflect.TypeOf(item)
		if foundType != currentType {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("items contains disparate types. item (%d) %s is not a %s", i, currentType, foundType), errors.WithoutEvent())
		}
		msg, err := rw.newOplogMessage(ctx, opType, item, WithFieldMaskPaths(opts.WithFieldMaskPaths), WithNullPaths(opts.WithNullPaths))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}
		oplogMsgs = append(oplogMsgs, msg)
	}
	return oplogMsgs, nil
}

// addOplogForItems will add a multi-message oplog entry with one msg for each
// item. Items must all be of the same type.  Only CreateOp and DeleteOp are
// currently supported operations.
func (rw *Db) addOplogForItems(ctx context.Context, opType OpType, opts Options, ticket *store.Ticket, items []any) error {
	const op = "db.addOplogForItems"
	oplogArgs := opts.oplogOpts
	if ticket == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ticket", errors.WithoutEvent())
	}
	if len(items) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing items", errors.WithoutEvent())
	}
	if oplogArgs.metadata == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing metadata", errors.WithoutEvent())
	}
	if oplogArgs.wrapper == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing wrapper", errors.WithoutEvent())
	}

	oplogMsgs, err := rw.oplogMsgsForItems(ctx, opType, opts, items)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	replayable, err := validateOplogArgs(ctx, items[0], opts)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("oplog validation failed"), errors.WithoutEvent())
	}
	ticketer, err := oplog.NewTicketer(ctx, rw.UnderlyingDB()(), oplog.WithAggregateNames(true))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get Ticketer"), errors.WithoutEvent())
	}
	entry, err := oplog.NewEntry(
		ctx,
		replayable.TableName(),
		oplogArgs.metadata,
		oplogArgs.wrapper,
		ticketer,
	)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create oplog entry"), errors.WithoutEvent())
	}
	if err := entry.WriteEntryWith(
		ctx,
		&oplog.Writer{DB: rw.UnderlyingDB()()},
		ticket,
		oplogMsgs...,
	); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog entry"), errors.WithoutEvent())
	}
	return nil
}

func (rw *Db) addOplog(ctx context.Context, opType OpType, opts Options, ticket *store.Ticket, i any) error {
	const op = "db.addOplog"
	oplogArgs := opts.oplogOpts
	replayable, err := validateOplogArgs(ctx, i, opts)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	if ticket == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ticket", errors.WithoutEvent())
	}
	ticketer, err := oplog.NewTicketer(ctx, rw.UnderlyingDB()(), oplog.WithAggregateNames(true))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get Ticketer"), errors.WithoutEvent())
	}
	entry, err := oplog.NewEntry(
		ctx,
		replayable.TableName(),
		oplogArgs.metadata,
		oplogArgs.wrapper,
		ticketer,
	)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	msg, err := rw.newOplogMessage(ctx, opType, i, WithFieldMaskPaths(opts.WithFieldMaskPaths), WithNullPaths(opts.WithNullPaths))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	err = entry.WriteEntryWith(
		ctx,
		&oplog.Writer{DB: rw.UnderlyingDB()()},
		ticket,
		msg,
	)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog entry"), errors.WithoutEvent())
	}
	return nil
}

// WriteOplogEntryWith will write an oplog entry with the msgs provided for
// the ticket's aggregateName. No options are currently supported.
func (rw *Db) WriteOplogEntryWith(ctx context.Context, wrapper wrapping.Wrapper, ticket *store.Ticket, metadata oplog.Metadata, msgs []*oplog.Message, _ ...Option) error {
	const op = "db.WriteOplogEntryWith"
	if wrapper == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing wrapper")
	}
	if ticket == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ticket")
	}
	if len(msgs) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing msgs")
	}
	if rw.underlying == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	if len(metadata) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing metadata")
	}
	ticketer, err := oplog.NewTicketer(ctx, rw.UnderlyingDB()(), oplog.WithAggregateNames(true))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get Ticketer"))
	}

	entry, err := oplog.NewEntry(
		ctx,
		ticket.Name,
		metadata,
		wrapper,
		ticketer,
	)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create oplog entry"))
	}
	err = entry.WriteEntryWith(
		ctx,
		&oplog.Writer{DB: rw.UnderlyingDB()()},
		ticket,
		msgs...,
	)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog entry"))
	}
	return nil
}

func (rw *Db) newOplogMessage(ctx context.Context, opType OpType, i any, opt ...Option) (*oplog.Message, error) {
	const op = "db.newOplogMessage"
	opts := GetOpts(opt...)
	replayable, ok := i.(oplog.ReplayableMessage)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "not a replayable interface", errors.WithoutEvent())
	}
	msg := oplog.Message{
		Message:  i.(proto.Message),
		TypeName: replayable.TableName(),
	}
	switch opType {
	case CreateOp:
		msg.OpType = oplog.OpType_OP_TYPE_CREATE
	case UpdateOp:
		msg.OpType = oplog.OpType_OP_TYPE_UPDATE
		msg.FieldMaskPaths = opts.WithFieldMaskPaths
		msg.SetToNullPaths = opts.WithNullPaths
	case DeleteOp:
		msg.OpType = oplog.OpType_OP_TYPE_DELETE
	case CreateItemsOp:
		msg.OpType = oplog.OpType_OP_TYPE_CREATE_ITEMS
	case DeleteItemsOp:
		msg.OpType = oplog.OpType_OP_TYPE_DELETE_ITEMS
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("operation type %v is not supported", opType), errors.WithoutEvent())
	}
	return &msg, nil
}
