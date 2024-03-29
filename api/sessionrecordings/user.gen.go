// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecordings

import (
	"github.com/hashicorp/boundary/api/scopes"
)

type User struct {
	Id          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Scope       *scopes.ScopeInfo `json:"scope,omitempty"`
}
