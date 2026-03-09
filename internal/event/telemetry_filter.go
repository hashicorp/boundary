// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"errors"
	"reflect"
	"strings"

	"google.golang.org/protobuf/proto"
)

// Any fields in these packages should be treated as atomic structures
var coreProtoPackages = map[string]bool{
	"anypb":           true,
	"apipb":           true,
	"durationpb":      true,
	"emptypb":         true,
	"fieldmaskpb":     true,
	"sourcecontextpb": true,
	"structpb":        true,
	"timestamppb":     true,
	"typepb":          true,
	"wrapperspb":      true,
}

// protoFilter is a signature for a struct field validation test
type protoFilter func(field reflect.StructField) bool

// telemetryFilter checks a struct field should be included in observation telemetry data
func telemetryFilter(field reflect.StructField) bool {
	if field.Tag.Get("eventstream") == "observation" && field.Tag.Get("class") == "public" {
		return true
	}
	return false
}

// filterValue will preserve or zero a value based on if it is classed as observable
func filterValue(fv reflect.Value, isObservable bool) {
	if isObservable {
		return // let data persist to telemetry
	}

	// check for nil value (prevent panics)
	if fv == reflect.ValueOf(nil) {
		return
	}

	if fv.Kind() == reflect.Ptr {
		fv = fv.Elem()
	}

	// check to see if it's an exported struct field
	if !fv.CanSet() {
		return
	}

	fv.SetZero()

	return
}

// packageNameFromType extracts the package for a type for use with
// core protobuf type checks.
func packageNameFromType(fieldType reflect.Type) string {
	typeSegments := strings.Split(fieldType.String(), ".")
	pkg := strings.TrimLeft(typeSegments[0], "*")
	return pkg
}

// recurseStructureWithProtoFilter will recursively traverse the data struct passed in, and run
// a filter function (filterFunc) on struct fields to decide if they should be preserved or cleared.
// isObservable specifies if the level the current value resides in is considered observable or not.
func recurseStructureWithProtoFilter(value reflect.Value, filterFunc protoFilter, isObservable bool) error {
	kind := value.Kind()

	switch kind {
	case reflect.Interface, reflect.Ptr:
		value = value.Elem()
		return recurseStructureWithProtoFilter(value, filterFunc, isObservable)
	case reflect.Map:
		iter := value.MapRange()
		for iter.Next() {
			mVal := iter.Value()
			k := iter.Key()
			vKind := mVal.Kind()
			if vKind == reflect.Ptr || vKind == reflect.Interface {
				mVal = mVal.Elem()
				vKind = mVal.Kind()
			}
			if coreProtoPackages[packageNameFromType(mVal.Type())] {
				if !isObservable {
					value.SetMapIndex(k, reflect.Value{})
				}
				continue
			}
			switch vKind {
			case reflect.Struct, reflect.Array, reflect.Slice:
				if err := recurseStructureWithProtoFilter(mVal, filterFunc, isObservable); err != nil {
					return err
				}
				if mVal.IsValid() && mVal.IsZero() {
					value.SetMapIndex(k, reflect.Value{})
				}
			default:
				if !isObservable {
					value.SetMapIndex(k, reflect.Value{})
				}
			}
		}
		return nil
	case reflect.Array, reflect.Slice:
		if value.Len() > 0 {
			sliceType := value.Index(0).Type()
			isCoreProto := coreProtoPackages[packageNameFromType(sliceType)]
			zeroCount := 0
			if !isCoreProto {
				for i := 0; i < value.Len(); i++ {
					sVal := value.Index(i)
					sKind := sVal.Kind()
					if sKind == reflect.Ptr || sKind == reflect.Interface {
						sVal = sVal.Elem()
					}
					if err := recurseStructureWithProtoFilter(sVal, filterFunc, isObservable); err != nil {
						return err
					}
					if sVal.IsValid() && sVal.IsZero() {
						zeroCount++
					}
				}
			}
			// if slice is empty after processing, we can zero its length
			// if an array is empty, zero its contents
			if (zeroCount == value.Len() || (isCoreProto && !isObservable)) && value.CanSet() {
				switch kind {
				case reflect.Slice:
					value.SetLen(0)
				case reflect.Array:
					for i := 0; i < value.Len(); i++ {
						value.Index(i).SetZero()
					}
				}
			}
		}
	case reflect.Struct:
		fields := value.Type()
		for i := 0; i < fields.NumField(); i++ {
			field := fields.Field(i)
			v := value.Field(i)
			if !field.IsExported() {
				continue
			}
			isObservable := true
			if filterFunc != nil {
				isObservable = filterFunc(field)
			}
			// structures in core proto packages are not recursively filtered
			if coreProtoPackages[packageNameFromType(field.Type)] {
				if !isObservable {
					v.SetZero()
				}
				continue
			}
			if err := recurseStructureWithProtoFilter(v, filterFunc, isObservable); err != nil {
				return err
			}
		}
		return nil
	default:
		// any other non structured type, we will output or not via filterValue
		filterValue(value, isObservable)
		return nil
	}

	return nil
}

// filterProtoMessage recursively traverses the proto.Message passed in, applying the specified filter
// to decide if it will clear or preserve fields. It operates on a clone of the supplied proto, so as to preserve
// the original data.
func filterProtoMessage(msg proto.Message, filterFunc protoFilter) (proto.Message, error) {
	if msg == nil {
		return nil, errors.New("nil message")
	}

	cloneMsg := proto.Clone(msg)
	err := recurseStructureWithProtoFilter(reflect.ValueOf(cloneMsg), filterFunc, false)
	return cloneMsg, err
}
