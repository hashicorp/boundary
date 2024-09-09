// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package managedgroups

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type OidcManagedGroupAttributes struct {
	Filter string `json:"filter,omitempty"`
}

func AttributesMapToOidcManagedGroupAttributes(in map[string]any) (*OidcManagedGroupAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out OidcManagedGroupAttributes
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

func (pt *ManagedGroup) GetOidcManagedGroupAttributes() (*OidcManagedGroupAttributes, error) {
	if pt.Type != "oidc" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but managed-group is of type %s", "oidc", pt.Type)
	}
	return AttributesMapToOidcManagedGroupAttributes(pt.Attributes)
}
