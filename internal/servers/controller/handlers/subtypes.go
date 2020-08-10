package handlers

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func StructToProto(fields *structpb.Struct, p proto.Message) error {
	js, err := fields.MarshalJSON()
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(js, p); err != nil {
		return err
	}
	return nil
}

func ProtoToStruct(p proto.Message) (*structpb.Struct, error) {
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
