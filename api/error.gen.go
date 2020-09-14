// Code generated by "make api"; DO NOT EDIT.
package api

import "bytes"

type Error struct {
	Status  int32         `json:"status,omitempty"`
	Code    string        `json:"code,omitempty"`
	Message string        `json:"message,omitempty"`
	Details *ErrorDetails `json:"details,omitempty"`

	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n Error) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n Error) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}

type ErrorListResult struct {
	Items            []*Error
	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n ErrorListResult) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n ErrorListResult) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}

type ErrorDeleteResult struct {
	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n ErrorDeleteResult) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n ErrorDeleteResult) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}
