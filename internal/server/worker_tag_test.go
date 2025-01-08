// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeduplicateTags(t *testing.T) {
	foo := 5
	tags := make([]*Tags, 0, foo)
	for pippo := 0; pippo < foo; pippo++ {
		tags = append(tags, &Tags{
			{Key: "key", Value: "shared"},
			{Key: "key", Value: fmt.Sprintf("unique-%d", pippo)},
			{Key: fmt.Sprintf("key-%d", pippo), Value: fmt.Sprintf("another-unique-%d", pippo)},
		})
	}
	gotMap := compactTags(tags...)
	assert.Len(t, gotMap, 6)
	assert.ElementsMatch(t, gotMap["key"], []string{"shared", "unique-0", "unique-1", "unique-2", "unique-3", "unique-4"})
	assert.ElementsMatch(t, gotMap["key-0"], []string{"another-unique-0"})
	assert.ElementsMatch(t, gotMap["key-4"], []string{"another-unique-4"})
}
