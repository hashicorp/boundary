// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"
)

// TestAssertOutputFields asserts that the output fields of a group match the expected fields
// fields that is nil or empty in the result will throw an error if they are listed in expectedFields
// e.g. members when group does not contain any members
func TestAssertOutputFields(t *testing.T, p proto.Message, expectFields []string) {
	msg := p.ProtoReflect()
	descriptor := msg.Descriptor()
	for i := 0; i < descriptor.Fields().Len(); i++ {
		fd := descriptor.Fields().Get(i)
		fieldName := string(fd.Name())
		if !slices.Contains(expectFields, fieldName) {
			require.Falsef(t, msg.Has(fd), "expect field '%s' to be empty but got %+v", fd.Name(), msg.Get(fd).Interface())
			continue
		}
		require.Truef(t, msg.Has(fd), "expect field '%s' NOT be empty but got %+v", fd.Name(), msg.Get(fd).Interface())
	}
}
