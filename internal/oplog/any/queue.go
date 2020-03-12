package any

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/gogo/protobuf/proto"
	types "github.com/gogo/protobuf/types"
)

// Queue provides a FIFO queue
type Queue struct {
	// QueueBuffer provides a buffer for the queue
	QueueBuffer
	// Catalog provides a TypeCatalog for the types added to the queue
	Catalog *TypeCatalog
}

// Add pb message to queue
func (r *Queue) Add(m proto.Message, t OpType) error {
	type_usl := reflect.TypeOf(m).String()
	value, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("error marshaling add parameter: %w", err)
	}
	msg := &Any{
		Anything: &types.Any{
			TypeUrl: type_usl,
			Value:   value,
		},
		Type: t,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error marhaling the anything msg for Add: %w", err)
	}
	err = binary.Write(r, binary.LittleEndian, int32(len(data)))
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
func (r *Queue) Remove() (proto.Message, OpType, error) {
	var n int32
	err := binary.Read(r, binary.LittleEndian, &n)
	if err != nil {
		return nil, 0, err // intentionally not wrapping error so client can test for sentinel EOF error
	}
	data := r.Next(int(n))
	msg := new(Any)
	err = proto.Unmarshal(data, msg)
	if err != nil {
		return nil, 0, fmt.Errorf("error marshaling the anything msg for Remove: %w", err)
	}
	if msg.Anything.Value == nil {
		return nil, 0, nil
	}
	any, err := r.Catalog.Get(msg.Anything.TypeUrl)
	if err != nil {
		return nil, 0, fmt.Errorf("error getting the anything.TypeUrl for Remove: %w", err)
	}
	pm := any.(proto.Message)
	if err = proto.Unmarshal(msg.Anything.Value, pm); err != nil {
		return nil, 0, fmt.Errorf("error unmarshaling the anything value for Remove: %w", err)
	}
	return pm, msg.Type, err
}
