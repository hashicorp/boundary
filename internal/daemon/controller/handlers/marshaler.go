// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"
)

// JSONMarshaler provides marshaler used for marshaling all proto as JSON
// in a format expected by the user facing controller API.
func JSONMarshaler() *runtime.JSONPb {
	return &runtime.JSONPb{
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
}
