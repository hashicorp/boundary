// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package is

import "reflect"

// Nil checks if the interface is nil
func Nil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
