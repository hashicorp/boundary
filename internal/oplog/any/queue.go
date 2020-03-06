package any

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/gogo/protobuf/proto"
)

type Queue struct {
	QueueBuffer
	Catalog *TypeCatalog
}

// Add pb message to queue
func (r *Queue) Add(m proto.Message, t OpType) error {
	type_usl := reflect.TypeOf(m).String()
	value, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	msg := &Any{
		TypeUrl: type_usl,
		Value:   value,
		Type:    t,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	err = binary.Write(r, binary.LittleEndian, int32(len(data)))
	if err != nil {
		return err
	}
	n, err := r.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		panic(fmt.Sprintf("%d / %d", n, len(data)))
	}
	return nil
}

// Remove pb message from the queue and EOF if empty
func (r *Queue) Remove() (proto.Message, OpType, error) {
	var n int32
	err := binary.Read(r, binary.LittleEndian, &n)
	if err != nil {
		return nil, 0, err
	}
	data := r.Next(int(n))
	msg := new(Any)
	err = proto.Unmarshal(data, msg)
	if err != nil {
		return nil, 0, err
	}
	if msg.Value == nil {
		return nil, 0, nil
	}
	any, err := r.Catalog.Get(msg.TypeUrl)
	if err != nil {
		return nil, 0, err
	}
	pm := any.(proto.Message)
	err = proto.Unmarshal(msg.Value, pm)
	return pm, msg.Type, err
}
