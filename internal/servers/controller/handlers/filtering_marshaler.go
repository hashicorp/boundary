package handlers

import (
	"errors"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/go-bexpr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type filterMashaler struct {
	runtime.Marshaler
}

var _ runtime.Marshaler = &filterMashaler{}

type filterable interface {
	GetRequestedFilter() string
}

func (f *filterMashaler) Marshal(v interface{}) ([]byte, error) {
	filter := ""
	if m, ok := v.(filterable); !ok {
		return f.Marshaler.Marshal(v)
	} else {
		filter = m.GetRequestedFilter()
	}

	var pm proto.Message
	if m, ok := v.(proto.Message); !ok {
		return f.Marshaler.Marshal(v)
	} else {
		pm = m
	}
	clearFilterField(pm)

	var step map[string]interface{}
	b, err := f.Marshaler.Marshal(v)
	if err != nil {
		return nil, err
	}

	if err := f.Unmarshal(b, &step); err != nil {
		// Return filtering unmarshal error...
		return f.Marshaler.Marshal(v)
	}

	eval, err := bexpr.CreateEvaluator(filter)
	if err != nil {
		return f.Marshaler.Marshal(v)
	}
	vals, ok := step["items"].([]interface{})
	if !ok {
		return f.Marshaler.Marshal(v)
	}
	var newVal []interface{}
	for _, v := range vals {
		r, err := eval.Evaluate(v)
		if err != nil {
			return f.Marshaler.Marshal(v)
		}
		if r {
			newVal = append(newVal, v)
		}
	}

	step["items"] = newVal
	return f.Marshaler.Marshal(step)
}

func clearFilterField(in proto.Message) {
	refMsg := in.ProtoReflect()
	fd := refMsg.Descriptor().Fields().ByName("requested_filter")
	if fd == nil {
		return
	}
	refMsg.Clear(fd)
}

func filterItems(f string, in proto.Message) error {
	refMsg := in.ProtoReflect()

	fd := refMsg.Descriptor().Fields().ByName("items")
	if fd == nil {
		return errors.New("Couldn't find the item that should be filterable.")
	}
	itemList := refMsg.Get(fd).List()
	out := refMsg.NewField(fd).List()
	eval, err := bexpr.CreateEvaluator(f)
	if err != nil {
		return err
	}
	for i := 0; i < itemList.Len(); i++ {
		item := itemList.Get(i)
		match, err := eval.Evaluate(item.Message().Interface())
		if err != nil {
			return err
		}
		if match {
			out.Append(item)
		}
	}

	refMsg.Set(fd, protoreflect.ValueOfList(out))
	return nil
}
