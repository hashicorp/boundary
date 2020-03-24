package oplog

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	protoV1 "github.com/golang/protobuf/proto"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	_ "github.com/lib/pq"
	"google.golang.org/protobuf/proto"
)

// Message wraps a proto.Message and adds a operation type (Create, Update, Delete)
type Message struct {
	proto.Message
	TypeURL   string
	OpType    OpType
	FieldMask string
}

// Entry represents an oplog entry
type Entry struct {
	*store.Entry
	Cipherer wrapping.Wrapper `sql:"-"`
	Ticketer Ticketer         `sql:"-"`
}

func (e *Entry) vetAll() error {
	if e.Cipherer == nil {
		return errors.New("Cipherer is nil")
	}
	if e.Ticketer == nil {
		return errors.New("Ticketer is nil")
	}
	if e.Entry == nil {
		return errors.New("store.Entry is nil")
	}
	return nil
}

// TableName is needed to support gorm
func (*Entry) TableName() string {
	return "oplog_entries"
}

// UnmarshalData the data attribute from []byte (treated as a FIFO QueueBuffer) to a []proto.Message
func (e *Entry) UnmarshalData(types *TypeCatalog) ([]Message, error) {
	if len(e.Data) == 0 {
		return nil, fmt.Errorf("no Data to unmarshal")
	}
	msgs := []Message{}
	cp := make(QueueBuffer, len(e.Data))
	copy(cp, e.Data)
	queue := Queue{
		QueueBuffer: cp,
		Catalog:     types,
	}
	for {
		m, typ, mask, err := queue.Remove()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error removing item from queue: %w", err)
		}
		url, err := GetTypeURL(types, m)
		if err != nil {
			return nil, fmt.Errorf("error getting TypeURL: %w", err)
		}
		msgs = append(msgs, Message{Message: m, TypeURL: url, OpType: typ, FieldMask: mask})
	}
	return msgs, nil
}

// WriteEntryWith the []proto.Message marshaled into the entry data as a FIFO QueueBuffer
// if CryptoService != nil then the data is authentication encrypted
func (e *Entry) WriteEntryWith(ctx context.Context, tx Writer, ticket *store.Ticket, msgs ...*Message) error {
	if err := e.vetAll(); err != nil {
		return fmt.Errorf("error vetting entry for writing: %w", err)
	}
	if ticket == nil || ticket.Version == 0 {
		return errors.New("bad ticket")
	}

	queue := Queue{}
	for _, m := range msgs {
		if err := queue.Add(m.Message, m.TypeURL, m.OpType, WithFieldMask(m.FieldMask)); err != nil {
			return fmt.Errorf("error adding message to queue: %w", err)
		}
	}
	e.Data = append(e.Data, []byte(queue.QueueBuffer)...)

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
// if CryptoService != nil then the data is authentication encrypted
func (e *Entry) Write(ctx context.Context, tx Writer, ticket *store.Ticket) error {
	if err := e.vetAll(); err != nil {
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
	d, err := e.Cipherer.Encrypt(ctx, e.Data, nil)
	if err != nil {
		return fmt.Errorf("error encrypting entry: %w", err)
	}
	blob, err := protoV1.Marshal(d)
	if err != nil {
		return fmt.Errorf("error marshaling encrypted data: %w", err)
	}
	e.Data = []byte(base64.RawURLEncoding.EncodeToString(blob))
	return nil
}

// DecryptData will decrypt the entry's data using its Cipherer (wrapping.Wrapper)
func (e *Entry) DecryptData(ctx context.Context) error {
	blob, err := base64.RawURLEncoding.DecodeString(string(e.Data))
	if err != nil {
		return fmt.Errorf("error decoding encrypted data: %w", err)
	}
	var msg wrapping.EncryptedBlobInfo
	err = protoV1.Unmarshal(blob, &msg)
	if err != nil {
		return fmt.Errorf("error unmarshaling encrypted data: %w", err)
	}
	d, err := e.Cipherer.Decrypt(ctx, &msg, nil)
	if err != nil {
		return fmt.Errorf("error decrypting data: %w", err)
	}
	e.Data = d
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
		em.SetTableName(origTableName + tableSuffix)
		switch m.OpType {
		case OpType_CreateOp:
			if err := tx.Create(m.Message); err != nil {
				return fmt.Errorf("replay error: %w", err)
			}
		case OpType_UpdateOp:
			if err := tx.Update(m.Message, m.FieldMask); err != nil {
				return fmt.Errorf("replay error: %w", err)
			}
		case OpType_DeleteOp:
			if err := tx.Delete(m.Message); err != nil {
				return fmt.Errorf("replay error: %w", err)
			}
		default:
			return fmt.Errorf("replay error: unhandled operation %T", m.OpType)
		}
	}
	return nil
}
