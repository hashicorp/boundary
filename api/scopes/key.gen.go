// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package scopes

import (
	"time"
)

type Key struct {
	Id          string        `json:"id,omitempty"`
	Scope       *ScopeInfo    `json:"scope,omitempty"`
	Purpose     string        `json:"purpose,omitempty"`
	CreatedTime time.Time     `json:"created_time,omitempty"`
	Type        string        `json:"type,omitempty"`
	Versions    []*KeyVersion `json:"versions,omitempty"`
}
