package handlers

import (
	"reflect"

	"github.com/hashicorp/boundary/internal/errors"
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
	const op = "handlers.NewFilter"
	if f == "" {
		return &Filter{}, nil
	}
	e, err := bexpr.CreateEvaluator(f, bexpr.WithTagName("json"), bexpr.WithHookFn(wellKnownTypeFilterHook))
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("couldn't build filter"), errors.WithCode(errors.InvalidParameter))
	}
	return &Filter{eval: e}, nil
}

// Match returns if the provided interface matches the filter.
// If the filter does not match the structure of the object being Matched, false is returned.
// TODO: Support more than just matching against the item being filtered.  Also allow matching against
//   values in the request or the request context itself.
func (f *Filter) Match(item interface{}) bool {
	if f.eval == nil {
		return true
	}
	m, err := f.eval.Evaluate(filterItem{Item: item})
	// There isn't a clear way to differentiate between a JSON Pointer which doesn't represent
	// the structure of the object being Matched and a JSON Pointer which references a field which
	// is part of a sub structure that is nil in this item. Because of this, any filter which would
	// result in an error using the underlying library is simply interpreted as not a match.
	return err == nil && m
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
