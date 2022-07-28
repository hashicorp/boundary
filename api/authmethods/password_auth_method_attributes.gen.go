// Code generated by "make api"; DO NOT EDIT.
package authmethods

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type PasswordAuthMethodAttributes struct {
	MinLoginNameLength uint32 `json:"min_login_name_length,omitempty"`
	MinPasswordLength  uint32 `json:"min_password_length,omitempty"`
}

func AttributesMapToPasswordAuthMethodAttributes(in map[string]interface{}) (*PasswordAuthMethodAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out PasswordAuthMethodAttributes
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

func (pt *AuthMethod) GetPasswordAuthMethodAttributes() (*PasswordAuthMethodAttributes, error) {
	return AttributesMapToPasswordAuthMethodAttributes(pt.Attributes)
}
