// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mql

import (
	"fmt"
	"reflect"
)

// isNil reports if a is nil
func isNil(a any) bool {
	if a == nil {
		return true
	}
	switch reflect.TypeOf(a).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Chan, reflect.Slice, reflect.Func:
		return reflect.ValueOf(a).IsNil()
	}
	return false
}

// panicIfNil will panic if a is nil
func panicIfNil(a any, caller, missing string) {
	if isNil(a) {
		panic(fmt.Sprintf("%s: missing %s", caller, missing))
	}
}

func pointer[T any](input T) *T {
	return &input
}
