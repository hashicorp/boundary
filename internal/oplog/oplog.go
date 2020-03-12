package oplog

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog/any"
	"github.com/hashicorp/watchtower/internal/oplog/store"
)

// Message wraps a proto.Message and adds a operation type (Create, Update, Delete)
type Message struct {
	proto.Message
	Type any.OpType
}

// Entry represents an oplog entry
type Entry struct {
	*store.Entry
	Cipherer wrapping.Wrapper `sql:"-"`
	Ticketer Ticketer         `sql:"-"`
}

func (e *Entry) vetAll() error {
	if e.Cipherer == nil {
		return fmt.Errorf("Cipherer is nil")
	}
	if e.Ticketer == nil {
		return fmt.Errorf("Ticketer is nil")
	}
	if e.Entry == nil {
		return fmt.Errorf("store.Entry is nil")
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
			return nil, err
		}
		msgs = append(msgs, Message{m, typ})

	}
	return msgs, nil
}

// WriteEntryWith the []proto.Message marshaled into the entry data as a FIFO QueueBuffer
// if CryptoService != nil then the data is encrypted and HMAC'd
func (e *Entry) WriteEntryWith(ctx context.Context, tx Writer, ticket *store.Ticket, msgs ...*Message) error {
	if err := e.vetAll(); err != nil {
		return err
	}
	if ticket == nil || ticket.Version == 0 {
		return fmt.Errorf("bad ticket")
	}

	queue := any.Queue{}
	for _, m := range msgs {
		if err := queue.Add(m.Message, m.Type); err != nil {
			return err
		}
	}
	e.Data = append(e.Data, []byte(queue.QueueBuffer)...)

	if e.Cipherer != nil {
		if err := e.EncryptData(ctx); err != nil {
			return err
		}
	}
	if err := tx.Create(e); err != nil {
		return err
	}
	return e.Ticketer.Redeem(ticket)
}

// Write the entry as is with whatever it has for e.Data marshaled into a FIFO QueueBuffer
// if CryptoService != nil then the data is encrypted and HMAC'd
func (e *Entry) Write(ctx context.Context, tx Writer, ticket *store.Ticket) error {
	if err := e.vetAll(); err != nil {
		return err
	}
	if ticket == nil || ticket.Version == 0 {
		return fmt.Errorf("bad ticket")
	}
	if e.Cipherer != nil {
		if err := e.EncryptData(ctx); err != nil {
			return err
		}
	}
	if err := tx.Create(e); err != nil {
		return err
	}
	return e.Ticketer.Redeem(ticket)
}

func (e *Entry) EncryptData(ctx context.Context) error {
	d, err := e.Cipherer.Encrypt(ctx, e.Data, nil)
	if err != nil {
		return err
	}
	blob, err := proto.Marshal(d)
	if err != nil {
		return err
	}
	e.Data = []byte(base64.RawURLEncoding.EncodeToString(blob))
	return nil
}

func (e *Entry) DecryptData(ctx context.Context) error {
	blob, err := base64.RawURLEncoding.DecodeString(string(e.Data))
	if err != nil {
		return err
	}
	var msg wrapping.EncryptedBlobInfo
	err = proto.Unmarshal(blob, &msg)
	if err != nil {
		return err
	}
	d, err := e.Cipherer.Decrypt(ctx, &msg, nil)
	if err != nil {
		return err
	}
	e.Data = d
	return nil
}
