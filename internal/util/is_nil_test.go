// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package util_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/util"
	"github.com/stretchr/testify/assert"
)

func Test_IsNil(t *testing.T) {
	t.Parallel()

	var testErrNilPtr *testError
	var testMapNilPtr map[string]struct{}
	var testArrayNilPtr *[1]string
	var testChanNilPtr *chan string
	var testSliceNilPtr *[]string
	var testFuncNil func()

	var testChanString chan string

	tc := []struct {
		i    any
		want bool
	}{
		{i: &testError{}, want: false},
		{i: testError{}, want: false},
		{i: &map[string]struct{}{}, want: false},
		{i: map[string]struct{}{}, want: false},
		{i: [1]string{}, want: false},
		{i: &[1]string{}, want: false},
		{i: &testChanString, want: false},
		{i: "string", want: false},
		{i: []string{}, want: false},
		{i: func() {}, want: false},
		{i: nil, want: true},
		{i: testErrNilPtr, want: true},
		{i: testMapNilPtr, want: true},
		{i: testArrayNilPtr, want: true},
		{i: testChanNilPtr, want: true},
		{i: testChanString, want: true},
		{i: testSliceNilPtr, want: true},
		{i: testFuncNil, want: true},
	}

	for i, tc := range tc {
		t.Run(fmt.Sprintf("test #%d", i+1), func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(tc.want, util.IsNil(tc.i))
		})
	}
}

type testError struct{}

func (*testError) Error() string { return "error" }
