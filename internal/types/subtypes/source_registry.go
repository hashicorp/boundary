// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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

func init() {
	globalSourceRegistry = sourceRegistry{
		m: make(map[protoreflect.FullName]protoreflect.FieldDescriptor),
	}

	protoregistry.GlobalTypes.RangeMessages(func(m protoreflect.MessageType) bool {
		d := m.Descriptor()
		if err := globalSourceRegistry.register(d); err != nil {
			panic(err)
		}
		return true
	})
}

var globalSourceRegistry sourceRegistry

// sourceRegistry is collection of proto messages with a corresponding
// field descriptor that can be used to determine the Subtype for the message.
type sourceRegistry struct {
	sync.RWMutex

	m map[protoreflect.FullName]protoreflect.FieldDescriptor
}

func (s *sourceRegistry) register(d protoreflect.MessageDescriptor) error {
	s.Lock()
	defer s.Unlock()

	fn := d.FullName()

	if _, present := s.m[fn]; present {
		return fmt.Errorf("proto message %s already registered", fn)
	}

	fields := d.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)

		opts := f.Options().(*descriptorpb.FieldOptions)
		isSourceId := proto.GetExtension(opts, protooptions.E_SubtypeSourceId).(bool)
		if isSourceId {
			s.m[fn] = f
		}
	}
	return nil
}

func (s *sourceRegistry) get(d protoreflect.MessageDescriptor) protoreflect.FieldDescriptor {
	s.RLock()
	defer s.RUnlock()

	return s.m[d.FullName()]
}

// sourceIdFieldDescriptor is used by the AttributeTransformInterceptor to retrieve
// a proto FieldDescriptor of an id field that can be used to determine
// the given Message's subtype.
func sourceIdFieldDescriptor(d protoreflect.MessageDescriptor) protoreflect.FieldDescriptor {
	return globalSourceRegistry.get(d)
}
