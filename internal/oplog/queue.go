// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/protobuf/proto"
)

// Queue provides a FIFO queue
type Queue struct {
	// Buffer for the queue
	bytes.Buffer

	// Catalog provides a TypeCatalog for the types added to the queue
	Catalog *TypeCatalog

	mx sync.Mutex
}

// add message to queue.  typeName defines the type of message added to the
// queue and allows the msg to be removed using a TypeCatalog with a
// coresponding typeName entry. OpType defines the msg's operation (create, add,
// update, etc).  If OpType == OpType_OP_TYPE_UPDATE, the WithFieldMaskPaths()
// and SetToNullPaths() options are supported.
func (q *Queue) add(ctx context.Context, m proto.Message, typeName string, t OpType, opt ...Option) error {
	const op = "oplog.(Queue).Add"
	// we're not checking the Catalog for nil, since it's not used
	// when Adding messages to the queue
	opts := GetOpts(opt...)
	withFieldMasks := opts[optionWithFieldMaskPaths].([]string)
	withNullPaths := opts[optionWithSetToNullPaths].([]string)
	withOperationOptions := opts[optionWithOperationOptions].([]dbw.Option)

	if _, ok := m.(ReplayableMessage); !ok {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%T is not a replayable message", m))
	}
	value, err := proto.Marshal(m)
	if err != nil {
		return errors.New(ctx, errors.Encode, op, "error marshaling add parameter", errors.WithWrap(err))
	}
	if t == OpType_OP_TYPE_UPDATE {
		if len(withFieldMasks) == 0 && len(withNullPaths) == 0 {
			return errors.New(ctx, errors.InvalidParameter, op, "missing field masks or null paths for update")
		}
		fMasks := withFieldMasks
		if fMasks == nil {
			fMasks = []string{}
		}
		nullPaths := withNullPaths
		if nullPaths == nil {
			nullPaths = []string{}
		}
		i, _, _, err := dbw.Intersection(fMasks, nullPaths)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if len(i) != 0 {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("field masks and null paths intersect with: %s", i))
		}
	}
	var operationOpts *OperationOptions
	if len(withOperationOptions) > 0 {
		dbwOptions := dbw.GetOpts(withOperationOptions...)
		operationOpts, err = convertFromDbwOpts(ctx, dbwOptions)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	msg := &AnyOperation{
		TypeName:      typeName,
		Value:         value,
		OperationType: t,
		FieldMask:     &field_mask.FieldMask{Paths: withFieldMasks},
		NullMask:      &field_mask.FieldMask{Paths: withNullPaths},
		Options:       operationOpts,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.New(ctx, errors.Encode, op, "error marshaling message", errors.WithWrap(err))
	}
	q.mx.Lock()
	defer q.mx.Unlock()
	err = binary.Write(q, binary.LittleEndian, uint32(len(data)))
	if err != nil {
		return errors.New(ctx, errors.Io, op, "binary write error", errors.WithWrap(err))
	}
	n, err := q.Write(data)
	if err != nil {
		return errors.New(ctx, errors.Io, op, "error writing to queue buffer", errors.WithWrap(err))
	}
	if n != len(data) {
		return errors.New(ctx, errors.Io, op, fmt.Sprintf("error writing to queue buffer (incorrect number of bytes %d of %d)", n, len(data)))
	}
	return nil
}

type queueEntry struct {
	msg              proto.Message
	opType           OpType
	fieldMask        []string
	setToNullPaths   []string
	operationOptions *OperationOptions
}

// remove pb message from the queue and EOF if empty. It also returns the OpType
// for the msg and if it's OpType_OP_TYPE_UPDATE, the it will also return the
// fieldMask and setToNullPaths for the update operation.
func (q *Queue) remove(ctx context.Context) (*queueEntry, error) {
	const op = "oplog.(Queue).Remove"
	if q.Catalog == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil catalog")
	}
	q.mx.Lock()
	defer q.mx.Unlock()
	var n uint32
	err := binary.Read(q, binary.LittleEndian, &n)
	if err == io.EOF {
		return nil, err // intentionally not wrapping error, return io.EOF so client can handle it correctly
	}
	if err != nil {
		return nil, errors.New(ctx, errors.Io, op, "binary read error", errors.WithWrap(err))
	}
	data := q.Next(int(n))
	msg := new(AnyOperation)
	err = proto.Unmarshal(data, msg)
	if err != nil {
		return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
	}
	if msg.Value == nil {
		return nil, nil
	}
	any, err := q.Catalog.Get(ctx, msg.TypeName)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error getting the TypeName: %s", msg.TypeName)))
	}
	pm := any.(proto.Message)
	if err = proto.Unmarshal(msg.Value, pm); err != nil {
		return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling value", errors.WithWrap(err))
	}
	var masks, nullPaths []string
	if msg.OperationType == OpType_OP_TYPE_UPDATE {
		if msg.FieldMask != nil {
			masks = msg.FieldMask.GetPaths()
		}
		if msg.NullMask != nil {
			nullPaths = msg.NullMask.GetPaths()
		}
		if len(masks) == 0 && len(nullPaths) == 0 {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "field mask or null paths is required")
		}
	}
	return &queueEntry{
		msg:              pm,
		opType:           msg.OperationType,
		fieldMask:        masks,
		setToNullPaths:   nullPaths,
		operationOptions: msg.GetOptions(),
	}, nil
}
