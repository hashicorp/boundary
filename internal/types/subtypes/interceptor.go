// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"context"
	"errors"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// transformRequestAttributes will modify the request proto.Message, setting
// any subtype attribute fields into the corresponding strongly-typed struct
// for the subtype. It looks for some specific structure in the proto.Message
// to identify the correct subtype and apply the transformation.
//
// The first structure is a message that contains a single "item" that is a
// message that has a "type" and an "attrs" oneof for attributes:
//
//	message CreateFooRequest {
//	  item Foo = 1;
//	}
//	message Foo {
//	  string type = 1;
//	  // other fields
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 10 [(custom_options.v1.subtype) = "default"];
//	    // other subtype attributes types
//	  }
//	}
//
// The second structure is similar to the first, but rather then the type field
// being provided, an id field is set. Note this is a different id from the
// third structure. In this case it is an id for a related resource and the id
// is marked with the "subtype_source_id" custom option:
//
//	message CreateFooRequest {
//	  item Foo = 1;
//	}
//	message Foo {
//	  string bar_id = 1 [(custom_options.v1.subtype_source_id) = true];
//	  // other fields
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 10 [(custom_options.v1.subtype) = "default"];
//	    // other subtype attributes types
//	  }
//	}
//
// The third structure is a message that contains an id string and an "item"
// that is a message that has an "attrs" oneof for attributes:
//
//	message UpdateFooRequest {
//	  string id = 1;
//	  item Foo  = 2;
//	}
//	message Foo {
//	  // other fields
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 10 [(custom_options.v1.subtype) = "default"];
//	    // other subtype attributes types
//	  }
//	}
//
// The forth structure is a message that contains an id string and an "attrs" oneof for
// attributes:
//
//	message FooActionRequest {
//	  string id = 1;
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 10 [(custom_options.v1.subtype) = "default"];
//	    // other subtype attributes types
//	  }
//	}
//
// Also note that for any of the id based lookups to function, the file that contains
// the proto.Message definition must set the "domain" custom option.
func transformRequestAttributes(req proto.Message) error {
	r := req.ProtoReflect()
	fields := r.Descriptor().Fields()

	itemField := fields.ByName("item")
	idField := fields.ByName("id")
	attributesField := fields.ByName("attributes")

	fieldValue := func(m protoreflect.Message, fd protoreflect.FieldDescriptor) string {
		if fd == nil {
			return ""
		}
		return m.Get(fd).String()
	}

	var st globals.Subtype
	switch {
	case itemField != nil:
		itemR := itemField.Message()
		if itemR == nil {
			return nil
		}
		id := fieldValue(r, idField)

		item := r.Get(itemField).Message().Interface()
		itemFields := itemR.Fields()

		typeField := itemFields.ByName("type")
		t := fieldValue(item.ProtoReflect(), typeField)

		sourceIdField := sourceIdFieldDescriptor(item.ProtoReflect().Descriptor())
		sourceId := fieldValue(item.ProtoReflect(), sourceIdField)

		switch {
		case idField != nil && id != "":
			st = globals.ResourceInfoFromPrefix(id).Subtype
		case sourceIdField != nil && sourceId != "":
			st = globals.ResourceInfoFromPrefix(sourceId).Subtype
		case typeField != nil && t != "":
			st = globals.Subtype(t)
		default: // need either type or id
			return nil
		}
		return convertAttributesToSubtype(item, st)
	case idField != nil && attributesField != nil:
		id := r.Get(idField).String()
		st = globals.ResourceInfoFromPrefix(id).Subtype
		return convertAttributesToSubtype(req, st)
	}
	return nil
}

func transformResponseItemAttributes(ctx context.Context, item proto.Message) error {
	r := item.ProtoReflect()
	desc := r.Descriptor()

	typeField := desc.Fields().ByName("type")
	if typeField == nil {
		// not an item with subtypes
		return nil
	}

	attrsField := desc.Oneofs().ByName("attrs")
	if attrsField == nil {
		// not an item with attrs oneof
		return nil
	}

	if r.WhichOneof(attrsField) == nil {
		// attrs field is not set, nothing to do
		return nil
	}

	st := globals.Subtype(item.ProtoReflect().Get(typeField).String())
	return convertAttributesToDefault(ctx, item, st)
}

func transformRequest(ctx context.Context, msg proto.Message) error {
	fqn := msg.ProtoReflect().Descriptor().FullName()
	if fn, ok := globalTransformationRegistry.requestTransformationFuncs[fqn]; ok {
		return fn(ctx, msg)
	}
	return transformRequestAttributes(msg)
}

// transformResponseAttributes will modify the response proto.Message, setting
// any subtype attribute fields into the default structpb.Struct field. It looks
// for some specific structure in the proto.Message to identify that it is a
// message that needs transformation.
//
// The first structure is a message that contains a single "item" that is a
// message that has an "attrs" oneof for attributes:
//
//	message CreateFooResponse {
//	  item Foo = 1;
//	}
//	message Foo {
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 10 [(custom_options.v1.subtype) = "default"];
//	    // other subtype attributes types
//	  }
//	}
//
// The second structure is a message that contains a single "items" that is a
// slice of item messages that have an "attrs" oneof for attributes:
//
//	message ListFooResponse {
//	  items []Foo = 1;
//	}
//	message Foo {
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 10 [(custom_options.v1.subtype) = "default"];
//	    // other subtype attributes types
//	  }
//	}
func transformResponseAttributes(ctx context.Context, res proto.Message) error {
	r := res.ProtoReflect()
	fields := r.Descriptor().Fields()

	itemField := fields.ByName("item")
	itemsField := fields.ByName("items")
	switch {
	case itemField != nil:
		if itemR := itemField.Message(); itemR == nil {
			return nil
		}

		item := r.Get(itemField).Message().Interface()
		return transformResponseItemAttributes(ctx, item)
	case itemsField != nil:
		if !itemsField.IsList() {
			return nil
		}
		items := r.Get(itemsField).List()

		for i := 0; i < items.Len(); i++ {
			item := items.Get(i).Message().Interface()
			if err := transformResponseItemAttributes(ctx, item); err != nil {
				return err
			}
		}
	}
	return nil
}

func transformResponse(ctx context.Context, msg proto.Message) error {
	fqn := msg.ProtoReflect().Descriptor().FullName()
	if fn, ok := globalTransformationRegistry.responseTransformationFuncs[fqn]; ok {
		return fn(ctx, msg)
	}
	return transformResponseAttributes(ctx, msg)
}

// AttributeTransformerInterceptor is a grpc server interceptor that will
// transform subtype attributes for requests and responses. This will only
// modify requests and responses that adhere to a specific structure and is done
// to support the use of a oneof for attributes to strongly type the attributes
// while allowing the JSON API to provide attributes via a single key.
//
// For example with a protobuf message definition like:
//
//	message Account {
//	  string id = 1;
//	  string type = 2;
//	  oneof attrs {
//	    google.protobuf.Struct attributes = 10 [(controller.custom_options.v1.subtype) = "default"];
//	    PasswordAttributes password_attributes = 20 [(controller.custom_options.v1.subtype) = "password"];
//	  }
//	}
//
//	message PasswordAttributes {
//	   string login_name = 1;
//	}
//
//	message AccountCreateRequest {
//	   Account item = 1;
//	}
//
//	message AccountCreateResponse {
//	   Account item = 1;
//	}
//
// And a create request with JSON request body like:
//
//	{
//	   "type": "password",
//	   "attributes": {
//	      "login_name": "tim"
//	   }
//	}
//
// Will result in a proto request like:
//
//	type:"password" attributes:{fields:{key:"login_name" value:{string_value:"tim"}}}
//
// This request will be transformed into:
//
//	type:"password" password_attributes:{login_name:"tim"}
func AttributeTransformerInterceptor(ctx context.Context) grpc.UnaryServerInterceptor {
	const op = "subtypes.AttributeTransformInterceptor"
	return func(interceptorCtx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if reqMsg, ok := req.(proto.Message); ok {
			if err := transformRequest(ctx, reqMsg); err != nil {
				fieldErrs := map[string]string{
					"attributes": "Attribute fields do not match the expected format.",
				}

				var unknownSubTypeIDErr *UnknownSubtypeIDError
				if errors.As(err, &unknownSubTypeIDErr) {
					fieldErrs["attributes"] = unknownSubTypeIDErr.Error()
				}

				return nil, handlers.InvalidArgumentErrorf("Error in provided request.", fieldErrs)
			}
		}

		res, handlerErr := handler(interceptorCtx, req)

		if res, ok := res.(proto.Message); ok {
			if err := transformResponse(ctx, res); err != nil {
				return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building attribute struct: %v", err)
			}
		}
		return res, handlerErr
	}
}
