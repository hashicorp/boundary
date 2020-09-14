// Code generated by "make api"; DO NOT EDIT.
package authmethods

import "bytes"

type PasswordAuthMethodAttributes struct {
	MinLoginNameLength uint32 `json:"min_login_name_length,omitempty"`
	MinPasswordLength  uint32 `json:"min_password_length,omitempty"`

	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n PasswordAuthMethodAttributes) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n PasswordAuthMethodAttributes) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}

type PasswordAuthMethodAttributesListResult struct {
	Items            []*PasswordAuthMethodAttributes
	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n PasswordAuthMethodAttributesListResult) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n PasswordAuthMethodAttributesListResult) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}

type PasswordAuthMethodAttributesDeleteResult struct {
	Existed          bool
	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n PasswordAuthMethodAttributesDeleteResult) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n PasswordAuthMethodAttributesDeleteResult) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}
