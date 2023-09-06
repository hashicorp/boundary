package event

import (
	"errors"
	"google.golang.org/protobuf/proto"
	"reflect"
)

// protoFilter is a signature for a struct field validation test
type protoFilter func(field reflect.StructField) bool

// telemetryFilter checks a struct field should be included in observation telemetry data
func telemetryFilter(field reflect.StructField) bool {
	if field.Tag.Get("eventstream") == "observation" {
		// log.Printf("%s is allowed by Tags (%s:\"%s\")", name, tag, tagValue)
		return true
	}
	return false
}

// filterValue will preserve or zero a value based on if it is classed as observable
func filterValue(fv reflect.Value, isObservable bool) error {
	if isObservable {
		return nil // let data persist to telemetry
	}

	// check for nil value (prevent panics)
	if fv == reflect.ValueOf(nil) {
		return nil
	}

	if fv.Kind() == reflect.Ptr {
		fv = fv.Elem()
	}

	// check to see if it's an exported struct field
	if !fv.CanSet() {
		return nil
	}

	fv.SetZero()

	return nil
}

func recurseStructureWithProtoFilter(value reflect.Value, filterFunc protoFilter, isObservable bool) error {

	kind := value.Kind()

	switch kind {
	case reflect.Interface, reflect.Ptr:
		value = value.Elem()
		return recurseStructureWithProtoFilter(value, filterFunc, isObservable)
	case reflect.Map:
		m := reflect.ValueOf(value)
		for _, k := range m.MapKeys() {
			mVal := m.MapIndex(k)
			if err := recurseStructureWithProtoFilter(mVal, filterFunc, isObservable); err != nil {
				return err
			}
		}
		return nil
	case reflect.Array, reflect.Slice:
		if isObservable {
			for i := 0; i < value.Len(); i++ {
				sVal := value.Index(i)
				if err := recurseStructureWithProtoFilter(sVal, filterFunc, isObservable); err != nil {
					return err
				}
			}
		} else {
			if kind == reflect.Slice {
				value.SetLen(0) // truncate
			} else {
				// fixed size, so we zero
				for i := 0; i < value.Len(); i++ {
					value.Index(i).SetZero()
				}
			}
		}
	case reflect.Struct:
		fields := value.Type()
		num := fields.NumField()
		for i := 0; i < num; i++ {
			field := fields.Field(i)
			v := value.Field(i)
			if !field.IsExported() {
				continue
			}
			isObservable := true
			if filterFunc != nil {
				isObservable = filterFunc(field)
			}
			if err := recurseStructureWithProtoFilter(v, filterFunc, isObservable); err != nil {
				return err
			}
		}
		return nil
	default:
		// any other non structured type, we will output or not via filterValue
		return filterValue(value, isObservable)
	}

	return nil
}

func filterProtoMessage(msg proto.Message, filterFunc protoFilter) (proto.Message, error) {
	if msg == nil {
		return nil, errors.New("nil message")
	}

	cloneMsg := proto.Clone(msg)
	err := recurseStructureWithProtoFilter(reflect.ValueOf(cloneMsg), filterFunc, false)
	return cloneMsg, err
}
