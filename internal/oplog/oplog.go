package oplog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	structwrapping "github.com/hashicorp/go-kms-wrapping/structwrapping"

	"github.com/hashicorp/boundary/internal/oplog/store"
	_ "github.com/lib/pq"
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
	Cipherer wrapping.Wrapper `sql:"-"`
	Ticketer Ticketer         `sql:"-"`
}

// Metadata provides meta information about the Entry
type Metadata map[string][]string

// NewEntry creates a new Entry
func NewEntry(aggregateName string, metadata Metadata, cipherer wrapping.Wrapper, ticketer Ticketer) (*Entry, error) {
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
		return nil, fmt.Errorf("error creating entry: %w", err)
	}
	return &entry, nil
}
func (e *Entry) validate() error {
	if e.Cipherer == nil {
		return errors.New("entry Cipherer is nil")
	}
	if e.Ticketer == nil {
		return errors.New("entry Ticketer is nil")
	}
	if e.Entry == nil {
		return errors.New("store.Entry is nil")
	}
	if e.Entry.Version == "" {
		return errors.New("entry version is not set")
	}
	if e.Entry.AggregateName == "" {
		return errors.New("entry aggregate name is not set")
	}
	return nil
}

// UnmarshalData the data attribute from []byte (treated as a FIFO QueueBuffer) to a []proto.Message
func (e *Entry) UnmarshalData(types *TypeCatalog) ([]Message, error) {
	if types == nil {
		return nil, errors.New("TypeCatalog is nil")
	}
	if len(e.Data) == 0 {
		return nil, errors.New("no Data to unmarshal")
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
			return nil, fmt.Errorf("error removing item from queue: %w", err)
		}
		name, err := types.GetTypeName(m)
		if err != nil {
			return nil, fmt.Errorf("error getting TypeName: %w", err)
		}
		msgs = append(msgs, Message{Message: m, TypeName: name, OpType: typ, FieldMaskPaths: fieldMaskPaths, SetToNullPaths: nullPaths})
	}
	return msgs, nil
}

// WriteEntryWith the []proto.Message marshaled into the entry data as a FIFO QueueBuffer
// if Cipherer != nil then the data is authentication encrypted
func (e *Entry) WriteEntryWith(ctx context.Context, tx Writer, ticket *store.Ticket, msgs ...*Message) error {
	if tx == nil {
		return errors.New("bad writer")
	}
	if err := e.validate(); err != nil {
		return fmt.Errorf("error vetting entry for writing: %w", err)
	}
	if ticket == nil || ticket.Version == 0 {
		return errors.New("bad ticket")
	}
	queue := Queue{}
	for _, m := range msgs {
		if m == nil {
			return errors.New("bad message")
		}
		if err := queue.Add(m.Message, m.TypeName, m.OpType, WithFieldMaskPaths(m.FieldMaskPaths), WithSetToNullPaths(m.SetToNullPaths)); err != nil {
			return fmt.Errorf("error adding message to queue: %w", err)
		}
	}
	e.Data = append(e.Data, []byte(queue.Bytes())...)

	if e.Cipherer != nil {
		if err := e.EncryptData(ctx); err != nil {
			return fmt.Errorf("error encrypting entry: %w", err)
		}
	}
	if err := tx.Create(e); err != nil {
		return fmt.Errorf("error writing data to storage: %w", err)
	}
	return e.Ticketer.Redeem(ticket)
}

// Write the entry as is with whatever it has for e.Data marshaled into a FIFO QueueBuffer
//  Cipherer != nil then the data is authentication encrypted
func (e *Entry) Write(ctx context.Context, tx Writer, ticket *store.Ticket) error {
	if err := e.validate(); err != nil {
		return fmt.Errorf("error vetting entry for writing: %w", err)
	}
	if ticket == nil || ticket.Version == 0 {
		return errors.New("bad ticket")
	}
	if e.Cipherer != nil {
		if err := e.EncryptData(ctx); err != nil {
			return fmt.Errorf("error encrypting entry: %w", err)
		}
	}
	if err := tx.Create(e); err != nil {
		return fmt.Errorf("error writing data to storage: %w", err)
	}
	return e.Ticketer.Redeem(ticket)
}

// EncryptData the entry's data using its Cipherer (wrapping.Wrapper)
func (e *Entry) EncryptData(ctx context.Context) error {
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, e.Cipherer, e.Entry, nil); err != nil {
		return fmt.Errorf("error encrypting entry: %w", err)
	}
	return nil
}

// DecryptData will decrypt the entry's data using its Cipherer (wrapping.Wrapper)
func (e *Entry) DecryptData(ctx context.Context) error {
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.UnwrapStruct(ctx, e.Cipherer, e.Entry, nil); err != nil {
		return fmt.Errorf("error decrypting entry: %w", err)
	}
	return nil
}

// Replay provides the ability to replay an entry.  you must initialize any new tables ending with the tableSuffix before
// calling Replay, otherwise you'll get "a table doesn't exist" error.
func (e *Entry) Replay(ctx context.Context, tx Writer, types *TypeCatalog, tableSuffix string) error {
	msgs, err := e.UnmarshalData(types)
	if err != nil {
		return fmt.Errorf("error on UnmarshalData: %w", err)
	}
	for _, m := range msgs {
		em, ok := m.Message.(ReplayableMessage)
		if !ok {
			return fmt.Errorf("%T is not a ReplayableMessage", m.Message)
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
				return fmt.Errorf("replay: %w", err)
			}
		}

		em.SetTableName(replayTable)
		switch m.OpType {
		case OpType_OP_TYPE_CREATE:
			if err := tx.Create(m.Message); err != nil {
				return fmt.Errorf("replay error: %w", err)
			}
		case OpType_OP_TYPE_UPDATE:
			if err := tx.Update(m.Message, m.FieldMaskPaths, m.SetToNullPaths); err != nil {
				return fmt.Errorf("replay error: %w", err)
			}
		case OpType_OP_TYPE_DELETE:
			if err := tx.Delete(m.Message); err != nil {
				return fmt.Errorf("replay error: %w", err)
			}
		default:
			return fmt.Errorf("replay error: unhandled operation %T", m.OpType)
		}
	}
	return nil
}
