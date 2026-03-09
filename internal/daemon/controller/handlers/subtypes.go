// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"runtime/trace"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func StructToProto(fields *structpb.Struct, p proto.Message, opt ...Option) error {
	if fields == nil {
		// If there is not struct, don't update the default proto message.
		return nil
	}
	js, err := fields.MarshalJSON()
	if err != nil {
		return err
	}
	opts := GetOpts(opt...)
	if opts.withDiscardUnknownFields {
		err = (protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(js, p))
	} else {
		err = protojson.Unmarshal(js, p)
	}
	if err != nil {
		return err
	}
	return nil
}

func ProtoToStruct(ctx context.Context, p proto.Message) (*structpb.Struct, error) {
	defer trace.StartRegion(ctx, "subtypes.ProtoToStruct").End()
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
