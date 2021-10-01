package oplog

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog/store"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/structwrapping"
	"google.golang.org/protobuf/proto"
)

// Version of oplog entries (among other things, it's used to manage upgrade compatibility when replicating)
const Version = "v1"

// Message wraps a proto.Message and adds a operation type (Create, Update, Delete)
type Message struct {
	proto.Message
	TypeName       string
	OpType         OpType
	FieldMaskPaths []string
	SetToNullPaths []string
}

// Entry represents an oplog entry
type Entry struct {
	*store.Entry
	Cipherer wrapping.Wrapper `gorm:"-"`
	Ticketer Ticketer         `gorm:"-"`
}

// Metadata provides meta information about the Entry
type Metadata map[string][]string

// NewEntry creates a new Entry
func NewEntry(aggregateName string, metadata Metadata, cipherer wrapping.Wrapper, ticketer Ticketer) (*Entry, error) {
	const op = "oplog.NewEntry"
	entry := Entry{
		Entry: &store.Entry{
			AggregateName: aggregateName,
			Version:       Version,
		},
		Cipherer: cipherer,
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
	if err := entry.validate(); err != nil {
		return nil, errors.WrapDeprecated(err, op)
	}
	return &entry, nil
}

func (e *Entry) validate() error {
	const op = "oplog.(Entry).validate"
	if e.Cipherer == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil cipherer")
	}
	if e.Ticketer == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil ticketer")
	}
	if e.Entry == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil entry")
	}
	if e.Entry.Version == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing entry version")
	}
	if e.Entry.AggregateName == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing entry aggregate name")
	}
	return nil
}

// UnmarshalData the data attribute from []byte (treated as a FIFO QueueBuffer) to a []proto.Message
func (e *Entry) UnmarshalData(types *TypeCatalog) ([]Message, error) {
	const op = "oplog.(Entry).UnmarshalData"
	if types == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil type catalog")
	}
	if len(e.Data) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing data")
	}
	msgs := []Message{}
	queue := Queue{
		Buffer:  *bytes.NewBuffer(e.Data),
		Catalog: types,
	}
	for {
		m, typ, fieldMaskPaths, nullPaths, err := queue.Remove()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.WrapDeprecated(err, op, errors.WithMsg("error removing item from queue"))
		}
		name, err := types.GetTypeName(m)
		if err != nil {
			return nil, errors.WrapDeprecated(err, op)
		}
		msgs = append(msgs, Message{Message: m, TypeName: name, OpType: typ, FieldMaskPaths: fieldMaskPaths, SetToNullPaths: nullPaths})
	}
	return msgs, nil
}

// WriteEntryWith the []proto.Message marshaled into the entry data as a FIFO QueueBuffer
// if Cipherer != nil then the data is authentication encrypted
func (e *Entry) WriteEntryWith(ctx context.Context, tx Writer, ticket *store.Ticket, msgs ...*Message) error {
	const op = "oplog.(Entry).WriteEntryWith"
	if tx == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if err := e.validate(); err != nil {
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
		if err := queue.Add(m.Message, m.TypeName, m.OpType, WithFieldMaskPaths(m.FieldMaskPaths), WithSetToNullPaths(m.SetToNullPaths)); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("error adding message to queue"))
		}
	}
	e.Data = append(e.Data, queue.Bytes()...)

	if e.Cipherer != nil {
		if err := e.EncryptData(ctx); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	if err := tx.Create(e); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error writing data to storage"))
	}
	if err := e.Ticketer.Redeem(ticket); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// Write the entry as is with whatever it has for e.Data marshaled into a FIFO QueueBuffer
//  Cipherer != nil then the data is authentication encrypted
func (e *Entry) Write(ctx context.Context, tx Writer, ticket *store.Ticket) error {
	const op = "oplog.(Entry).Write"
	if err := e.validate(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if ticket == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil ticket")
	}
	if ticket.Version == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ticket version")
	}
	if e.Cipherer != nil {
		if err := e.EncryptData(ctx); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	if err := tx.Create(e); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error writing data to storage"))
	}
	if err := e.Ticketer.Redeem(ticket); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// EncryptData the entry's data using its Cipherer (wrapping.Wrapper)
func (e *Entry) EncryptData(ctx context.Context) error {
	const op = "oplog.(Entry).EncryptData"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, e.Cipherer, e.Entry, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// DecryptData will decrypt the entry's data using its Cipherer (wrapping.Wrapper)
func (e *Entry) DecryptData(ctx context.Context) error {
	const op = "oplog.(Entry).DecryptData"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.UnwrapStruct(ctx, e.Cipherer, e.Entry, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

// Replay provides the ability to replay an entry.  you must initialize any new tables ending with the tableSuffix before
// calling Replay, otherwise you'll get "a table doesn't exist" error.
func (e *Entry) Replay(ctx context.Context, tx Writer, types *TypeCatalog, tableSuffix string) error {
	const op = "oplog.(Entry).Replay"
	msgs, err := e.UnmarshalData(types)
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
			when we go to implement snapshots we may very well need to refactor this create table
			choice... there are many issues with doing the "create" in this manner:
				* the perms needed to create a table and possible security issues
				* the fk references would be to the original tables, not the new replay tables.
			It may be a better choice to just create separate schemas for replay named blue and green
			since we need at min of two replay tables definitions. if we went with separate schemas they
			could be create with a boundary cli cmd that had appropriate privs (reducing security issues)
			and the separate schemas wouldn't have the fk reference issues mentioned above.
		*/
		replayTable := origTableName + tableSuffix
		if !tx.hasTable(replayTable) {
			if err := tx.createTableLike(origTableName, replayTable); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}

		em.SetTableName(replayTable)
		switch m.OpType {
		case OpType_OP_TYPE_CREATE:
			if err := tx.Create(m.Message); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		case OpType_OP_TYPE_UPDATE:
			if err := tx.Update(m.Message, m.FieldMaskPaths, m.SetToNullPaths); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		case OpType_OP_TYPE_DELETE:
			if err := tx.Delete(m.Message); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid operation %T", m.OpType))
		}
	}
	return nil
}
