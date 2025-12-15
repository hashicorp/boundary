// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompactTags(t *testing.T) {
	foo := 5
	tags := make([]*Tags, 0, foo)
	for pippo := 0; pippo < foo; pippo++ {
		thisTag := make(Tags)
		thisTag["key"] = []string{"shared", fmt.Sprintf("unique-%d", pippo)}
		thisTag[fmt.Sprintf("key-%d", pippo)] = []string{fmt.Sprintf("another-unique-%d", pippo)}
		tags = append(tags, &thisTag)
	}
	gotMap := compactTags(tags...)
	assert.Len(t, gotMap, 6)
	assert.ElementsMatch(t, gotMap["key"], []string{"shared", "unique-0", "unique-1", "unique-2", "unique-3", "unique-4"})
	assert.ElementsMatch(t, gotMap["key-0"], []string{"another-unique-0"})
	assert.ElementsMatch(t, gotMap["key-4"], []string{"another-unique-4"})
}

func TestConvertToTag(t *testing.T) {
	numTags := 5
	wantSlice := make([]*Tag, 0, numTags)
	tags := make(Tags)
	for i := 0; i < numTags; i++ {
		thisTag := &Tag{
			Key:   fmt.Sprintf("key-%d", i),
			Value: fmt.Sprintf("unique-%d", i),
		}
		wantSlice = append(wantSlice, thisTag)
		tags[fmt.Sprintf("key-%d", i)] = []string{fmt.Sprintf("unique-%d", i)}
	}
	gotTags := tags.convertToTag()

	assert.ElementsMatch(t, gotTags, wantSlice)
}

func TestConvertToTags(t *testing.T) {
	numTags := 5
	tagsSlice := make([]*Tag, 0, numTags)
	wantTags := make(Tags)
	for i := 0; i < numTags; i++ {
		thisTag := &Tag{
			Key:   fmt.Sprintf("key-%d", i),
			Value: fmt.Sprintf("unique-%d", i),
		}
		tagsSlice = append(tagsSlice, thisTag)
		wantTags[fmt.Sprintf("key-%d", i)] = []string{fmt.Sprintf("unique-%d", i)}
	}
	tags := convertToTags(tagsSlice)

	assert.Equal(t, len(tags), len(wantTags))
	for k, v := range tags {
		assert.ElementsMatch(t, v, wantTags[k])
	}
}
