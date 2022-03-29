package subtypes

import (
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	defaultSubtype = "default"
)

func init() {
	globalAttributeKeys = attributeKeys{
		m: make(map[protoreflect.FullName]fieldMap),
	}

	protoregistry.GlobalTypes.RangeMessages(func(m protoreflect.MessageType) bool {
		d := m.Descriptor()
		if err := globalAttributeKeys.register(d); err != nil {
			panic(err)
		}
		return true
	})
}

type fieldMap map[Subtype]protoreflect.FieldDescriptor

type attributeKeys struct {
	sync.RWMutex
	m map[protoreflect.FullName]fieldMap
}

var globalAttributeKeys attributeKeys

// register examines the given protobuf MessageDescriptor for fields that have
// the Subtype protobuf extension. It uses these to build a fieldMap of subtype
// strings to the protobuf FieldDescriptors. If the message does not have any
// subtypes it will not be registered, but no error is returned, allowing this
// to be called on any protobuf message. However, if a message has subtypes but
// does not provide a field with a subtype of "default" an error is returned.
func (ak attributeKeys) register(d protoreflect.MessageDescriptor) error {
	ak.Lock()
	defer ak.Unlock()

	if ak.m == nil {
		ak.m = make(map[protoreflect.FullName]fieldMap)
	}

	fn := d.FullName()

	if _, ok := ak.m[fn]; ok {
		return fmt.Errorf("proto message %s already registered", fn)
	}

	km := make(fieldMap, 0)

	fields := d.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)

		opts := f.Options().(*descriptorpb.FieldOptions)
		st := proto.GetExtension(opts, protooptions.E_Subtype).(string)
		if st != "" {
			km[Subtype(st)] = f
		}
	}

	// no subtypes were found, so nothing needs to be registered
	if len(km) <= 0 {
		return nil
	}

	// If a message has subtypes, it must provide a "default" to support plugins.
	if _, ok := km[defaultSubtype]; !ok {
		return fmt.Errorf("proto message %s with subtype attributes but no 'default'", fn)
	}

	ak.m[fn] = km

	return nil
}

// protoAttributeField retrieves the FieldDescriptor for a given subtype's
// attribute fields. If the corresponding protobuf message has not been
// registered it will return an error.
func (ak attributeKeys) protoAttributeField(d protoreflect.MessageDescriptor, t Subtype) (protoreflect.FieldDescriptor, error) {
	ak.RLock()
	defer ak.RUnlock()

	fn := d.FullName()

	km, ok := ak.m[fn]
	if !ok {
		return nil, fmt.Errorf("proto message %s not registered", fn)
	}

	tt, ok := km[t]
	if ok {
		return tt, nil
	}

	tt, ok = km[defaultSubtype]
	if !ok {
		return nil, fmt.Errorf("missing default for %s", fn)
	}
	return tt, nil
}

// TODO: fix doc
// protoAttributeField is used by the attrMarshaler to translate between JSON
// formats for the API and for the protobuf messages. It expects a
// proto.Message with a OneOf field for the subtype attributes and the subtype
// string. It returns the string for the JSON key that that should be used for
// the subtype's attributes fields.
func protoAttributeField(msg proto.Message, t Subtype) (protoreflect.FieldDescriptor, error) {
	d := msg.ProtoReflect().Descriptor()
	return globalAttributeKeys.protoAttributeField(d, t)
}
