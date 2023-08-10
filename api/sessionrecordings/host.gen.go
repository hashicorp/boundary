// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package sessionrecordings

type Host struct {
	Id           string                 `json:"id,omitempty"`
	HostCatalog  *HostCatalog           `json:"host_catalog,omitempty"`
	Name         string                 `json:"name,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Type         string                 `json:"type,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
	ExternalId   string                 `json:"external_id,omitempty"`
	ExternalName string                 `json:"external_name,omitempty"`
}
