// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package roles

type GrantJson struct {
	Id      string   `json:"id,omitempty"`
	Ids     []string `json:"ids,omitempty"`
	Type    string   `json:"type,omitempty"`
	Actions []string `json:"actions,omitempty"`
}
