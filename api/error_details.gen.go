// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

type ErrorDetails struct {
	RequestFields []*FieldError   `json:"request_fields,omitempty"`
	WrappedErrors []*WrappedError `json:"wrapped_errors,omitempty"`
}
