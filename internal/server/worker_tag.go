// Copyright IBM Corp. 2020, 2025
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

// convertToTags converts a slice of Tags to a map of tags
func convertToTags(tags []*Tag) Tags {
	t := make(Tags)
	for _, tag := range tags {
		t[tag.Key] = append(t[tag.Key], tag.Value)
	}
	return t
}

// Tags allows us to scan a JSON array of worker tags from the database
type Tags map[string][]string

func (t *Tags) clone() Tags {
	newTags := make(map[string][]string)
	for k, v := range *t {
		for _, val := range v {
			newTags[k] = append(newTags[k], val)
		}
	}
	return newTags
}

// compactTags takes a list of Tags and returns a map of deduplicated, compacted tags
func compactTags(t ...*Tags) map[string][]string {
	compactedTags := make(map[Tag]struct{})
	for _, keys := range t {
		for key, tags := range *keys {
			for _, tag := range tags {
				compactedTags[Tag{Key: key, Value: tag}] = struct{}{}
			}
		}
	}

	tags := make(map[string][]string)
	for t := range compactedTags {
		tags[t.Key] = append(tags[t.Key], t.Value)
	}
	return tags
}

// convertToTag converts a map of tags to a slice of Tags
func (t *Tags) convertToTag() []*Tag {
	var tags []*Tag
	for key, values := range *t {
		for _, value := range values {
			tags = append(tags, &Tag{Key: key, Value: value})
		}
	}
	return tags
}

// Scan scans value into Tags, and implements the sql.Scanner interface
func (t *Tags) Scan(in any) error {
	var err error
	var test []*Tag
	switch v := in.(type) {
	case string:
		err = json.Unmarshal([]byte(v), &test)
	case []byte:
		err = json.Unmarshal([]byte(v), &test)
	default:
		return fmt.Errorf("cannot scan type %T into tags", in)
	}
	mapTags := make(map[string][]string)
	for _, tag := range test {
		mapTags[tag.Key] = append(mapTags[tag.Key], tag.Value)
	}
	*t = mapTags
	return err
}

// GormDataType gorm common data type (required)
func (t *Tags) GormDataType() string {
	return "tags"
}
