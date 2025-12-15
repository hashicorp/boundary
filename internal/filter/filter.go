// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package filter

import (
	"reflect"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// WellKnownTypeFilterHook is passed to bexpr to treat all proto well-known
// types as the types they wrap for comparison.
func WellKnownTypeFilterHook(v reflect.Value) reflect.Value {
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
