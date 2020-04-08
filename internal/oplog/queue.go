package oplog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

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

// Add pb message to queue
func (r *Queue) Add(m proto.Message, typeName string, t OpType, opt ...Option) error {
	// we're not checking the Catalog for nil, since it's not used
	// when Adding messages to the queue
	opts := GetOpts(opt...)
	withPaths := opts[optionWithFieldMaskPaths].([]string)

	value, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("error marshaling add parameter: %w", err)
	}
	msg := &AnyOperation{
		TypeName:      typeName,
		Value:         value,
		OperationType: t,
		FieldMask:     &field_mask.FieldMask{Paths: withPaths},
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error marhaling the msg for Add: %w", err)
	}
	r.mx.Lock()
	defer r.mx.Unlock()
	err = binary.Write(r, binary.LittleEndian, uint32(len(data)))
	if err != nil {
		return err
	}
	n, err := r.Write(data)
	if err != nil {
		return fmt.Errorf("error writing to queue buffer: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("error writing to queue buffer (incorrect number of bytes %d of %d)", n, len(data))
	}
	return nil
}

// Remove pb message from the queue and EOF if empty
func (r *Queue) Remove() (proto.Message, OpType, []string, error) {
	if r.Catalog == nil {
		return nil, OpType_UNKNOWN_OP, nil, errors.New("remove Catalog is nil")
	}
	r.mx.Lock()
	defer r.mx.Unlock()
	var n uint32
	err := binary.Read(r, binary.LittleEndian, &n)
	if err != nil {
		return nil, 0, nil, err // intentionally not wrapping error so client can test for sentinel EOF error
	}
	data := r.Next(int(n))
	msg := new(AnyOperation)
	err = proto.Unmarshal(data, msg)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("error marshaling the msg for Remove: %w", err)
	}
	if msg.Value == nil {
		return nil, 0, nil, nil
	}
	any, err := r.Catalog.Get(msg.TypeName)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("error getting the TypeName for Remove: %w", err)
	}
	pm := any.(proto.Message)
	if err = proto.Unmarshal(msg.Value, pm); err != nil {
		return nil, 0, nil, fmt.Errorf("error unmarshaling the value for Remove: %w", err)
	}
	return pm, msg.OperationType, msg.FieldMask.GetPaths(), nil
}
