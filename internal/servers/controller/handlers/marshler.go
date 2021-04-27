package handlers

import (
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"
)

var JSONMarshaler = &runtime.JSONPb{
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
}
