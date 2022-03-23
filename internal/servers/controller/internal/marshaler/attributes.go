package marshaler

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

func init() {
	globalAttributeKeys = attributeKeys{
		m: make(map[string]keyMap),
	}

	protoregistry.GlobalTypes.RangeMessages(func(m protoreflect.MessageType) bool {
		d := m.Descriptor()
		if err := globalAttributeKeys.register(d); err != nil {
			panic(err)
		}
		return true
	})
}

type keyMap map[string]string

type attributeKeys struct {
	sync.RWMutex
	m map[string]keyMap
}

var globalAttributeKeys attributeKeys

// register examines the given protobuf MessageDescriptor for fields that have
// the Subtype protobuf extension. It uses these to build a keyMap of subtype
// strings to the protobuf JSON keys. If the message does not have any subtypes
// it will not be registered, but no error is returned, allowing this to be
// called on any protobuf message. However, if a message has subtpyes but does
// not provide a field with a subtype of "default" an error is returned.
func (ak attributeKeys) register(d protoreflect.MessageDescriptor) error {
	ak.Lock()
	defer ak.Unlock()

	if ak.m == nil {
		ak.m = make(map[string]keyMap)
	}

	fn := string(d.FullName())

	if _, ok := ak.m[fn]; ok {
		return fmt.Errorf("proto message %s already registered", fn)
	}

	km := make(keyMap, 0)

	fields := d.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)

		opts := f.Options().(*descriptorpb.FieldOptions)
		st := proto.GetExtension(opts, protooptions.E_Subtype).(string)
		if st != "" {
			km[st] = string(f.Name())
		}
	}

	// no subtypes were found, so nothing needs to be registered
	if len(km) <= 0 {
		return nil
	}

	// If a message has subtypes, it must provide a "default" to support plugins.
	if _, ok := km["default"]; !ok {
		return fmt.Errorf("proto message %s with subtype attributes but no 'default'", fn)
	}

	ak.m[fn] = km
	fmt.Printf("%#v\n", ak.m)

	return nil
}

// protoAttributeKey retrieved the JSON key that should be used for the
// subtye's attribute fields. If the protobuf message has not been registered
// it will return an error.
func (ak attributeKeys) protoAttributeKey(d protoreflect.MessageDescriptor, t string) (string, error) {
	ak.RLock()
	defer ak.RUnlock()

	fmt.Printf("%#v\n", ak.m)
	fn := string(d.FullName())

	km, ok := ak.m[fn]
	if !ok {
		return "", fmt.Errorf("proto message %s not registered", fn)
	}

	tt, ok := km[t]
	if ok {
		return tt, nil
	}

	tt, ok = km["default"]
	if !ok {
		return "", fmt.Errorf("missing default for %s", fn)
	}
	return tt, nil
}

// protoAttributeKey is used by the AttrMarshaler to translate between JSON
// formats for the API and for the protobuf messages. It expects a
// proto.Message with a OneOf field for the subtype attributes and the subtype
// string. It returns the string for the JSON key that that should be used for
// the subtype's attributes fields.
func protoAttributeKey(v interface{}, t string) (string, error) {
	var msg proto.Message

	switch vv := v.(type) {
	case proto.Message:
		msg = vv
	default:
		derefed := reflect.ValueOf(v).Elem().Interface()
		switch vvv := derefed.(type) {
		case proto.Message:
			msg = vvv
		default:
			return "", fmt.Errorf("not a proto message: %T", v)
		}
	}

	d := msg.ProtoReflect().Descriptor()
	return globalAttributeKeys.protoAttributeKey(d, t)
}
