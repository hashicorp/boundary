package oplog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	common "github.com/hashicorp/boundary/internal/db/common"
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

// Add message to queue.  typeName defines the type of message added to the
// queue and allows the msg to be removed using a TypeCatalog with a
// coresponding typeName entry. OpType defines the msg's operation (create, add,
// update, etc).  If OpType == OpType_OP_TYPE_UPDATE, the WithFieldMaskPaths()
// and SetToNullPaths() options are supported.
func (q *Queue) Add(m proto.Message, typeName string, t OpType, opt ...Option) error {
	// we're not checking the Catalog for nil, since it's not used
	// when Adding messages to the queue
	opts := GetOpts(opt...)
	withFieldMasks := opts[optionWithFieldMaskPaths].([]string)
	withNullPaths := opts[optionWithSetToNullPaths].([]string)

	if _, ok := m.(ReplayableMessage); !ok {
		return fmt.Errorf("error %T is not a ReplayableMessage", m)
	}
	value, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("error marshaling add parameter: %w", err)
	}
	if t == OpType_OP_TYPE_UPDATE {
		if len(withFieldMasks) == 0 && len(withNullPaths) == 0 {
			return fmt.Errorf("queue add: missing field masks or null paths for update")
		}
		fMasks := withFieldMasks
		if fMasks == nil {
			fMasks = []string{}
		}
		nullPaths := withNullPaths
		if nullPaths == nil {
			nullPaths = []string{}
		}
		i, _, _, err := common.Intersection(fMasks, nullPaths)
		if err != nil {
			return fmt.Errorf("queue add: %w", err)
		}
		if len(i) != 0 {
			return fmt.Errorf("queue add: field masks and null paths intersect with: %s", i)
		}

	}
	msg := &AnyOperation{
		TypeName:      typeName,
		Value:         value,
		OperationType: t,
		FieldMask:     &field_mask.FieldMask{Paths: withFieldMasks},
		NullMask:      &field_mask.FieldMask{Paths: withNullPaths},
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error marhaling the msg for Add: %w", err)
	}
	q.mx.Lock()
	defer q.mx.Unlock()
	err = binary.Write(q, binary.LittleEndian, uint32(len(data)))
	if err != nil {
		return err
	}
	n, err := q.Write(data)
	if err != nil {
		return fmt.Errorf("error writing to queue buffer: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("error writing to queue buffer (incorrect number of bytes %d of %d)", n, len(data))
	}
	return nil
}

// Remove pb message from the queue and EOF if empty. It also returns the OpType
// for the msg and if it's OpType_OP_TYPE_UPDATE, the it will also return the
// fieldMask and setToNullPaths for the update operation.
func (q *Queue) Remove() (proto.Message, OpType, []string, []string, error) {
	if q.Catalog == nil {
		return nil, OpType_OP_TYPE_UNSPECIFIED, nil, nil, errors.New("remove Catalog is nil")
	}
	q.mx.Lock()
	defer q.mx.Unlock()
	var n uint32
	err := binary.Read(q, binary.LittleEndian, &n)
	if err != nil {
		return nil, 0, nil, nil, err // intentionally not wrapping error so client can test for sentinel EOF error
	}
	data := q.Next(int(n))
	msg := new(AnyOperation)
	err = proto.Unmarshal(data, msg)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error marshaling the msg for Remove: %w", err)
	}
	if msg.Value == nil {
		return nil, 0, nil, nil, nil
	}
	any, err := q.Catalog.Get(msg.TypeName)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error getting the TypeName for Remove: %w", err)
	}
	pm := any.(proto.Message)
	if err = proto.Unmarshal(msg.Value, pm); err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error unmarshaling the value for Remove: %w", err)
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
			return nil, 0, nil, nil, errors.New("error unmarshaling the value for Remove: field mask or null paths is required")
		}

	}
	return pm, msg.OperationType, masks, nullPaths, nil
}
