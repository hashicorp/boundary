// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
)

// A Tag is a custom key/value pair which can be attached to a Worker.
// Multiple Tags may contain the same key and different values in which
// case both key/value pairs are valid.  Tags can be sourced from either the
// worker's configuration or the api. key/value pairs can be the same from
// different sources.
type Tag struct {
	Key   string
	Value string
}

// Tags allows us to scan a JSON array of worker tags from the database
type Tags []*Tag

func (t *Tags) clone() Tags {
	newTags := make(Tags, 0, len(*t))
	for _, tag := range *t {
		newTags = append(newTags, &Tag{Key: tag.Key, Value: tag.Value})
	}
	return newTags
}

// DeduplicateTags takes a list of Tags and returns a map of deduplicated tags
func DeduplicateTags(t ...*Tags) map[string][]string {
	dedupedTags := make(map[Tag]struct{})
	for _, tags := range t {
		for _, tag := range *tags {
			dedupedTags[*tag] = struct{}{}
		}
	}

	tags := make(map[string][]string)
	for t := range dedupedTags {
		tags[t.Key] = append(tags[t.Key], t.Value)
	}
	return tags
}

// Scan scans value into Tags, and implements the sql.Scanner interface
func (t *Tags) Scan(in any) error {
	var err error
	switch v := in.(type) {
	case string:
		err = json.Unmarshal([]byte(v), &t)
	case []byte:
		err = json.Unmarshal(v, &t)
	default:
		return fmt.Errorf("cannot scan type %T into tags", in)
	}
	return err
}

// GormDataType gorm common data type (required)
func (t *Tags) GormDataType() string {
	return "tags"
}
