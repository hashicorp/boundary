package oplog

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	protoV1 "github.com/golang/protobuf/proto"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog/any"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"google.golang.org/protobuf/proto"
)

// Message wraps a proto.Message and adds a operation type (Create, Update, Delete)
type Message struct {
	proto.Message
	TypeURL string
	OpType  any.OpType
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
func (e *Entry) UnmarshalData(types *any.TypeCatalog) ([]Message, error) {
	if len(e.Data) == 0 {
		return nil, fmt.Errorf("no Data to unmarshal")
	}
	msgs := []Message{}
	cp := make(any.QueueBuffer, len(e.Data))
	copy(cp, e.Data)
	queue := any.Queue{
		QueueBuffer: cp,
		Catalog:     types,
	}
	for {
		m, typ, err := queue.Remove()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error removing item from queue: %w", err)
		}
		url, err := any.GetTypeURL(types, m)
		if err != nil {
			return nil, fmt.Errorf("error getting TypeURL: %w", err)
		}
		msgs = append(msgs, Message{Message: m, TypeURL: url, OpType: typ})
	}
	return msgs, nil
}

// WriteEntryWith the []proto.Message marshaled into the entry data as a FIFO QueueBuffer
// if CryptoService != nil then the data is encrypted and HMAC'd
func (e *Entry) WriteEntryWith(ctx context.Context, tx Writer, ticket *store.Ticket, msgs ...*Message) error {
	if err := e.vetAll(); err != nil {
		return fmt.Errorf("error vetting entry for writing: %w", err)
	}
	if ticket == nil || ticket.Version == 0 {
		return errors.New("bad ticket")
	}

	queue := any.Queue{}
	for _, m := range msgs {
		if err := queue.Add(m.Message, m.TypeURL, m.OpType); err != nil {
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
// if CryptoService != nil then the data is encrypted and HMAC'd
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
