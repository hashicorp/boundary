package subtypes

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

func convertAttributesToSubtype(msg proto.Message, st Subtype) error {
	r := msg.ProtoReflect()
	d := r.Descriptor()

	defaultAttrField, err := attributeField(d, defaultSubtype)
	if err != nil {
		// If unable to get a default attribute field, the message is either
		// not registered or not in the format needed for conversion, so no
		// conversion should be performed. The most likely case here is that
		// the message has not been changed to use a oneof for attributes yet.
		return nil
	}

	stAttrField, err := attributeField(d, st)
	if err != nil {
		// This error should not be possible, since any registration issue
		// would trigger the previous call, and if this particular subtype
		// is unknown, the default should be returned.
		return nil
	}

	if defaultAttrField == stAttrField {
		// no need to convert
		return nil
	}

	defaultAttrs, ok := r.Get(defaultAttrField).Message().Interface().(*structpb.Struct)
	if !ok {
		// This should not be possible since this is checked in
		// (attributeRegistry).register at initialization time and would panic
		// if this was the case.
		return fmt.Errorf("found default attribute field that is not structpb.Struct: %s %s", d.FullName(), defaultAttrField.FullName())
	}
	stAttrs := r.Get(stAttrField).Message().New().Interface()
	if err := structToProto(defaultAttrs, stAttrs); err != nil {
		return err
	}

	// implicitly clears any previously set oneof value
	r.Set(stAttrField, protoreflect.ValueOfMessage(stAttrs.ProtoReflect()))
	return nil
}

func convertAttributesToDefault(msg proto.Message, st Subtype) error {
	r := msg.ProtoReflect()
	d := r.Descriptor()

	defaultAttrField, err := attributeField(d, defaultSubtype)
	if err != nil {
		// If unable to get a default attribute field, the message is either
		// not registered or not in the format needed for conversion, so no
		// conversion should be performed. The most likely case here is that
		// the message has not been changed to use a oneof for attributes yet.
		return nil
	}

	stAttrField, err := attributeField(d, st)
	if err != nil {
		// This error should not be possible, since any registration issue
		// would trigger the previous call, and if this particular subtype
		// is unknown, the default should be returned.
		return nil
	}

	if defaultAttrField == stAttrField {
		// no need to convert
		return nil
	}

	stAttrs, ok := r.Get(stAttrField).Message().Interface().(proto.Message)
	if !ok {
		return fmt.Errorf("found subtype attribute field that is not proto.Message: %s %s", d.FullName(), stAttrField.FullName())
	}
	defaultAttrs, err := protoToStruct(stAttrs)
	if err != nil {
		return err
	}
	// implicitly clears any previously set oneof value
	r.Set(defaultAttrField, protoreflect.ValueOfMessage(defaultAttrs.ProtoReflect()))
	return nil
}

func structToProto(fields *structpb.Struct, p proto.Message) error {
	if fields == nil {
		// If there is no struct, don't update the default proto message.
		return nil
	}
	js, err := fields.MarshalJSON()
	if err != nil {
		return err
	}

	// TODO: replicate this logic but with a proto extension set on the Field
	// descriptor There are some attributes where we want to discard unknown
	// fields, while others that should error if there are unknown fields
	//
	// opts := GetOpts(opt...)
	// if opts.withDiscardUnknownFields {
	// 	err = (protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(js, p))
	// } else {
	// 	err = protojson.Unmarshal(js, p)
	// }

	err = protojson.Unmarshal(js, p)
	if err != nil {
		return err
	}
	return nil
}

func protoToStruct(p proto.Message) (*structpb.Struct, error) {
	js, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(p)
	if err != nil {
		return nil, err
	}
	st := &structpb.Struct{}
	if err := protojson.Unmarshal(js, st); err != nil {
		return nil, err
	}
	return st, nil
}

// Filterable converts a proto.Message so any subtype attributes fields are
// structed like the API so filter strings will be correctly applied. If the
// given proto.Message does not have any subtype attributes, the original
// proto.Message is returned.  To determine if the message needs
// transformation, it looks for a oneof field named "attrs". It also expects
// that there is a structpb.Struct field named "attributes" as part of the
// oneof. Thus the message must be like:
//
//    message Foo {
//      // other fields
//      oneof attrs {
//        google.protobuf.Struct attributes = 100;
//        // other attribute fields
//      }
//    }
//
// If the message does not conform to this structure,
// the original message is returned.
func Filterable(item proto.Message) (proto.Message, error) {
	clone := proto.Clone(item)
	r := clone.ProtoReflect()

	attrsField := r.Descriptor().Oneofs().ByName("attrs")
	if attrsField == nil {
		return item, nil
	}

	defaultAttrField := attrsField.Fields().ByName("attributes")
	if defaultAttrField == nil {
		return item, nil
	}

	var attr proto.Message
	var pbAttrs proto.Message
	var err error

	oneOfFields := attrsField.Fields()

	// Find the populated oneof field and turn it into a `*structpb.Struct`
	for i := 0; i < oneOfFields.Len(); i++ {
		attrField := oneOfFields.Get(i)
		attrMsg := r.Get(attrField).Message()
		attr = attrMsg.Interface()
		if attrMsg.IsValid() && attr != nil {
			pbAttrs, err = protoToStruct(attr)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	// no attrs set, so the original item can just be filtered as is
	if pbAttrs == nil {
		return item, nil
	}

	r.Set(defaultAttrField, protoreflect.ValueOfMessage(pbAttrs.ProtoReflect()))
	f, err := protoToStruct(r.Interface())
	if err != nil {
		return nil, err
	}
	return f, nil
}
