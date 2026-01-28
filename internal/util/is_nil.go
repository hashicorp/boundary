// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package util

import "reflect"

// IsNil checks if the interface is nil
func IsNil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Chan, reflect.Slice, reflect.Func:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
