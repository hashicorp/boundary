// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"context"
	"fmt"
	"runtime/trace"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

func convertAttributesToSubtype(msg proto.Message, st globals.Subtype) error {
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
	if err := handlers.StructToProto(defaultAttrs, stAttrs); err != nil {
		return err
	}

	// implicitly clears any previously set oneof value
	r.Set(stAttrField, protoreflect.ValueOfMessage(stAttrs.ProtoReflect()))
	return nil
}

func convertAttributesToDefault(ctx context.Context, msg proto.Message, st globals.Subtype) error {
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
	defaultAttrs, err := handlers.ProtoToStruct(ctx, stAttrs)
	if err != nil {
		return err
	}
	// implicitly clears any previously set oneof value
	r.Set(defaultAttrField, protoreflect.ValueOfMessage(defaultAttrs.ProtoReflect()))
	return nil
}

// Filterable converts a proto.Message so any subtype attributes fields are
// structed like the API so filter strings will be correctly applied. If the
// given proto.Message does not have any subtype attributes, the original
// proto.Message is returned.  To determine if the message needs
// transformation, it looks for a oneof field named "attrs". It also expects
// that there is a structpb.Struct field named "attributes" as part of the
// oneof. Thus the message must be like:
//
//	message Foo {
//	  // other fields
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 100;
//	    // other attribute fields
//	  }
//	}
//
// If the message does not conform to this structure,
// the original message is returned.
func Filterable(ctx context.Context, item proto.Message) (proto.Message, error) {
	defer trace.StartRegion(ctx, "subtypes.Filterable").End()
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

	oneofField := r.WhichOneof(attrsField)
	if oneofField == nil {
		// attrs field is not set, nothing to do
		return item, nil
	}

	attr = r.Get(oneofField).Message().Interface()
	pbAttrs, err = handlers.ProtoToStruct(ctx, attr)
	if err != nil {
		return nil, err
	}

	r.Set(defaultAttrField, protoreflect.ValueOfMessage(pbAttrs.ProtoReflect()))
	f, err := handlers.ProtoToStruct(ctx, r.Interface())
	if err != nil {
		return nil, err
	}
	return f, nil
}
