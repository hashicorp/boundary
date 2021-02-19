package handlers

import (
	"reflect"

	"github.com/hashicorp/go-bexpr"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// filterItem captures all the different namespaces that can be used when
// filtering an item.
type filterItem struct {
	Item interface{} `json:"item"`
}

type Filter struct {
	eval *bexpr.Evaluator
}

// NewFilter returns a Filter which can be evluated against.  An empty string paramter indicates
// all items passed to it should succeed.
func NewFilter(f string) (*Filter, error) {
	if f == "" {
		return &Filter{}, nil
	}
	e, err := bexpr.CreateEvaluator(f, bexpr.WithTagName("json"), bexpr.WithHookFn(wellKnownTypeFilterHook))
	if err != nil {
		return nil, err
	}
	return &Filter{eval: e}, nil
}

// Match returns if the provided interface matches the filter.
// TODO: Support more than just matching against the item being filtered.  Also allow matching against
//   values in the request or the request context itself.
func (f *Filter) Match(item interface{}) (bool, error) {
	if f.eval == nil {
		return true, nil
	}
	return f.eval.Evaluate(filterItem{Item: item})
}

// wellKnownTypeFilterHook is passed to bexpr to treat all proto well-known
// types as the types they wrap for comparison.
func wellKnownTypeFilterHook(v reflect.Value) reflect.Value {
	if !v.CanInterface() {
		return v
	}
	ret := v.Interface()
	switch pm := v.Interface().(type) {
	case *wrapperspb.BoolValue:
		ret = pm.GetValue()
	case *wrapperspb.BytesValue:
		ret = pm.GetValue()
	case *wrapperspb.StringValue:
		ret = pm.GetValue()
	case *wrapperspb.DoubleValue:
		ret = pm.GetValue()
	case *wrapperspb.FloatValue:
		ret = pm.GetValue()
	case *wrapperspb.Int32Value:
		ret = pm.GetValue()
	case *wrapperspb.Int64Value:
		ret = pm.GetValue()
	case *wrapperspb.UInt32Value:
		ret = pm.GetValue()
	case *wrapperspb.UInt64Value:
		ret = pm.GetValue()
	case *structpb.Struct:
		ret = pm.AsMap()
	case *timestamppb.Timestamp:
		ret = pm.AsTime()
	}
	return reflect.ValueOf(ret)
}
