// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package policies

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type StoragePolicyAttributes struct {
	RetainFor   *StoragePolicyRetainFor   `json:"retain_for,omitempty"`
	DeleteAfter *StoragePolicyDeleteAfter `json:"delete_after,omitempty"`
}

func AttributesMapToStoragePolicyAttributes(in map[string]any) (*StoragePolicyAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out StoragePolicyAttributes
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &out,
		TagName: "json",
	})
	if err != nil {
		return nil, fmt.Errorf("error creating mapstructure decoder: %w", err)
	}
	if err := dec.Decode(in); err != nil {
		return nil, fmt.Errorf("error decoding: %w", err)
	}
	return &out, nil
}

func (pt *Policy) GetStoragePolicyAttributes() (*StoragePolicyAttributes, error) {
	if pt.Type != "storage" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but policy is of type %s", "storage", pt.Type)
	}
	return AttributesMapToStoragePolicyAttributes(pt.Attributes)
}
