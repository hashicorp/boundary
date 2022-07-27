// Code generated by "make api"; DO NOT EDIT.
package credentials

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type JsonAttributes struct {
	Object     map[string]interface{} `json:"object,omitempty"`
	ObjectHmac string                 `json:"object_hmac,omitempty"`
}

func AttributesMapToJsonAttributes(in map[string]interface{}) (*JsonAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out JsonAttributes
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

func (pt *Credential) GetJsonAttributes() (*JsonAttributes, error) {
	if pt.Type != "json" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but credential is of type %s", "json", pt.Type)
	}
	return AttributesMapToJsonAttributes(pt.Attributes)
}
