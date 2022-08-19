// Code generated by "make api"; DO NOT EDIT.
package targets

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type TcpTargetAttributes struct {
	DefaultPort uint32 `json:"default_port,omitempty"`
}

func AttributesMapToTcpTargetAttributes(in map[string]interface{}) (*TcpTargetAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out TcpTargetAttributes
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

func (pt *Target) GetTcpTargetAttributes() (*TcpTargetAttributes, error) {
	if pt.Type != "tcp" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but target is of type %s", "tcp", pt.Type)
	}
	return AttributesMapToTcpTargetAttributes(pt.Attributes)
}
