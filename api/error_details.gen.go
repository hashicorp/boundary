// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

type ErrorDetails struct {
	RequestFields []*FieldError   `json:"request_fields,omitempty"`
	WrappedErrors []*WrappedError `json:"wrapped_errors,omitempty"`
}
