// Code generated by "make api"; DO NOT EDIT.
package managedgroups

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type LdapManagedGroupAttributes struct {
	GroupNames []string `json:"group_names,omitempty"`
}

func AttributesMapToLdapManagedGroupAttributes(in map[string]interface{}) (*LdapManagedGroupAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out LdapManagedGroupAttributes
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

func (pt *ManagedGroup) GetLdapManagedGroupAttributes() (*LdapManagedGroupAttributes, error) {
	if pt.Type != "ldap" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but managed-group is of type %s", "ldap", pt.Type)
	}
	return AttributesMapToLdapManagedGroupAttributes(pt.Attributes)
}
