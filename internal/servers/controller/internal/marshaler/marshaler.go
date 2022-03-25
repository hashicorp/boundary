// Package marshaler provides an implementation of the grpc-gateway
// runtime.Marshaler for use by the Controller.
//
// The marshaler manages any translation between the JSON API format and the
// format needed for the corresponding structs generated from protobuf.
// Currently the only translation need is for resources that have subtypes and
// that use an "attributes" key in the JSON for subtype-specific fields. The
// JSON API expects the subtype attributes as a single top-level key
// "attributes".  However, the protobuf messages use a oneof field for the
// attributes and therefore expect a specific attributes key for the subtype to
// be populated.  The marshaler will translate between these two formats. See
// Decode and Marshal for more details.
package marshaler

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// New creates a runtime.Marshaler.
func New() runtime.Marshaler {
	return &attrMarshaler{
		Marshaler: &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				// Ensures the json marshaler uses the snake casing as defined in the proto field names.
				UseProtoNames: true,
				// Do not add fields set to zero value to json.
				EmitUnpopulated: false,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				// Allows requests to contain unknown fields.
				DiscardUnknown: true,
			},
		},
	}
}

// attrMarshaler is a Marshaler that converts the attribute key in a JSON request
// to the key needed for protobuf OneOf.
type attrMarshaler struct {
	runtime.Marshaler
}

// NewDecoder returns a Decoder which reads a byte sequence from "r".
func (am *attrMarshaler) NewDecoder(r io.Reader) runtime.Decoder {
	d := json.NewDecoder(r)
	return DecoderWrapper{
		Decoder: d,
		wrapped: am.Marshaler,
	}
}

// DecoderWrapper is a wrapper around a runtime.Decoder via the wrapped runtime.Marshaler.
type DecoderWrapper struct {
	*json.Decoder
	wrapped runtime.Marshaler
}

// Decode decodes the stream into v.  It will transform the JSON bytes from the
// JSON api structure with "type" and "attributes" keys into the correct
// structure for decoding into a protobuf Message with a type and oneof for
// attributes. ie a request like:
//
//    {
//        "type": "password",
//        "attributes": {
//            "login_name": "tim",
//            "password": "secret"
//        }
//    }
//
// becomes:
//
//    {
//        "type": "password",
//        "password_attributes": {
//            "login_name": "tim",
//            "password": "secret"
//        }
//    }
//
// which allows for decoding into a protobuf Message like:
//
//    message Account {
//      string type = 80;
//      oneof {
//        PasswordAccountAttributes password_attributes = 101;
//      }
//    }
//
//    message PasswordAccountAttributes {
//      string login_name = 10;
//      google.protobuf.StringValue password = 20;
//    }
func (d DecoderWrapper) Decode(v interface{}) error {
	var m map[string]interface{}
	if err := d.Decoder.Decode(&m); err != nil {
		return err
	}
	if items, ok := m["items"]; ok {
		if vv, ok := repeatedType(v); ok {
			if i, ok := items.([]interface{}); ok {
				for _, item := range i {
					if ii, ok := item.(map[string]interface{}); ok {
						apiToProtoAttrs(vv, ii)
					}
				}
			}
		}
	} else {
		apiToProtoAttrs(v, m)
	}

	b, _ := json.Marshal(&m)
	wd := d.wrapped.NewDecoder(bytes.NewReader([]byte(b)))
	return wd.Decode(v)
}

func apiToProtoAttrs(v interface{}, m map[string]interface{}) map[string]interface{} {
	if t, ok := m["type"]; ok {
		tt := t.(string)
		if attrs, ok := m["attributes"]; ok {
			if key, err := protoAttributeKey(v, tt); err == nil {
				if key != "attributes" {
					m[key] = attrs
					delete(m, "attributes")
				}
			}
		}
	}
	return m
}

func protoToApiAttrs(v interface{}, m map[string]interface{}) map[string]interface{} {
	if t, ok := m["type"]; ok {
		tt := t.(string)
		if key, err := protoAttributeKey(v, tt); err == nil {
			if key != "attributes" {
				if attrs, ok := m[key]; ok {
					m["attributes"] = attrs
					delete(m, key)
				}
			}
		}
	}
	return m
}

func repeatedType(v interface{}) (protoreflect.MessageDescriptor, bool) {
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
			return nil, false
		}
	}

	fields := msg.ProtoReflect().Descriptor().Fields()
	itemsField := fields.ByName("items")
	if itemsField == nil {
		return nil, false
	}

	if !itemsField.IsList() {
		return nil, false
	}
	return itemsField.Message(), true
}

func (am *attrMarshaler) marshal(w io.Writer, v interface{}) error {
	var buf bytes.Buffer
	wrappedEnc := am.Marshaler.NewEncoder(&buf)
	if err := wrappedEnc.Encode(v); err != nil {
		return err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		return err
	}
	if items, ok := m["items"]; ok {
		if d, ok := repeatedType(v); ok {
			if i, ok := items.([]interface{}); ok {
				for _, item := range i {
					if ii, ok := item.(map[string]interface{}); ok {
						protoToApiAttrs(d, ii)
					}
				}
			}
		}
	} else {
		protoToApiAttrs(v, m)
	}

	enc := json.NewEncoder(w)
	return enc.Encode(&m)
}

// Marshal converts the given struct into a JSON []byte.
// It will transform a protobuf Message with a type and oneof for attributes
// into the correc structure for the JSON api with "type" and "attribute" keys.
// ie a protobuf message like:
//
//    message Account {
//      string type = 80;
//      oneof {
//        PasswordAccountAttributes password_attributes = 101;
//      }
//    }
//
//    message PasswordAccountAttributes {
//      string login_name = 10;
//      google.protobuf.StringValue password = 20;
//    }
//
// The would otherwise be marshaled into JSON like:
//
//    {
//        "type": "password",
//        "password_attributes": {
//            "login_name": "tim",
//            "password": "secret"
//        }
//    }
//
// becomes:
//
//    {
//        "type": "password",
//        "attributes": {
//            "login_name": "tim",
//            "password": "secret"
//        }
//    }
func (am *attrMarshaler) Marshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := am.marshal(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NewEncoder returns an Encoder which writes a byte sequence into "w".
// This does not appear to be used by grpc gateway, but is implemented for
// completeness.
func (am *attrMarshaler) NewEncoder(w io.Writer) runtime.Encoder {
	return runtime.EncoderFunc(func(v interface{}) error {
		return am.marshal(w, v)
	})
}

// Unmarshal unmarshals data into v.
// This does not appear to be used by grpc gateway, but is implemented for
// completeness.
func (am *attrMarshaler) Unmarshal(data []byte, v interface{}) error {
	buf := bytes.NewBuffer(data)
	d := am.NewDecoder(buf)
	return d.Decode(v)
}
