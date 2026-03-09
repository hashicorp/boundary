// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"reflect"
	"testing"

	"github.com/hashicorp/eventlogger/filters/encrypt"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// NewEncryptFilter is a copy of event.NewEncryptFilter since importing it would
// case circular deps.  The primary reason for this test func is to make sure
// the proper IgnoreTypes are included for testing.
func NewEncryptFilter(t testing.TB, w wrapping.Wrapper) *encrypt.Filter {
	t.Helper()
	return &encrypt.Filter{
		Wrapper: w,
		IgnoreTypes: []reflect.Type{
			reflect.TypeOf(&fieldmaskpb.FieldMask{}),
		},
	}
}
