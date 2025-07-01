// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mql

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

type validator struct {
	fn  validateFunc
	typ string
}

// validateFunc is used to validate a column value by converting it as needed,
// validating the value, and returning the converted value
type validateFunc func(columnValue string) (columnVal any, err error)

// fieldValidators takes a model and returns a map of field names to validate
// functions.  Supported options: WithIgnoreFields
func fieldValidators(model reflect.Value, opt ...Option) (map[string]validator, error) {
	const op = "mql.fieldValidators"
	switch {
	case !model.IsValid():
		return nil, fmt.Errorf("%s: missing model: %w", op, ErrInvalidParameter)
	case (model.Kind() != reflect.Struct && model.Kind() != reflect.Pointer),
		model.Kind() == reflect.Pointer && model.Elem().Kind() != reflect.Struct:
		return nil, fmt.Errorf("%s: model must be a struct or a pointer to a struct: %w", op, ErrInvalidParameter)
	}
	var m reflect.Value = model
	if m.Kind() != reflect.Struct {
		m = model.Elem()
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	fValidators := make(map[string]validator)
	for i := 0; i < m.NumField(); i++ {
		field := m.Type().Field(i)
		if slices.Contains(opts.withIgnoredFields, field.Name) {
			continue
		}

		var fName string
		switch {
		case opts.withColumnFieldTag != "":
			tagValue := field.Tag.Get(opts.withColumnFieldTag)
			if tagValue != "" {
				parts := strings.SplitN(tagValue, ",", 2)
				fName = parts[0]
			}
			if fName == "" {
				return nil, fmt.Errorf("%s: field %q has an invalid tag %q: %w", op, field.Name, opts.withColumnFieldTag, ErrInvalidParameter)
			}
		default:
			fName = strings.ToLower(field.Name)
		}

		// get a string val of the field type, then strip any leading '*' so we
		// can simplify the switch below when dealing with types like *int and int.
		fType := strings.TrimPrefix(m.Type().Field(i).Type.String(), "*")
		switch fType {
		case "float32", "float64":
			fValidators[fName] = validator{fn: validateFloat, typ: "float"}
		case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
			fValidators[fName] = validator{fn: validateInt, typ: "int"}
		case "time.Time":
			fValidators[fName] = validator{fn: validateDefault, typ: "time"}
		default:
			fValidators[fName] = validator{fn: validateDefault, typ: "default"}
		}
	}
	return fValidators, nil
}

// by default, we'll use a no op validation
func validateDefault(s string) (any, error) {
	return s, nil
}

func validateInt(s string) (any, error) {
	const op = "mql.validateInt"
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: value %q is not an int: %w", op, s, ErrInvalidParameter)
	}
	return i, nil
}

func validateFloat(s string) (any, error) {
	const op = "mql.validateFloat"
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, fmt.Errorf("%s: value %q is not float: %w", op, s, ErrInvalidParameter)
	}
	return f, nil
}
