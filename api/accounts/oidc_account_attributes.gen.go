// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package accounts

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type OidcAccountAttributes struct {
	Issuer         string                 `json:"issuer,omitempty"`
	Subject        string                 `json:"subject,omitempty"`
	FullName       string                 `json:"full_name,omitempty"`
	Email          string                 `json:"email,omitempty"`
	TokenClaims    map[string]interface{} `json:"token_claims,omitempty"`
	UserinfoClaims map[string]interface{} `json:"userinfo_claims,omitempty"`
}

func AttributesMapToOidcAccountAttributes(in map[string]interface{}) (*OidcAccountAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out OidcAccountAttributes
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

func (pt *Account) GetOidcAccountAttributes() (*OidcAccountAttributes, error) {
	if pt.Type != "oidc" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but account is of type %s", "oidc", pt.Type)
	}
	return AttributesMapToOidcAccountAttributes(pt.Attributes)
}
