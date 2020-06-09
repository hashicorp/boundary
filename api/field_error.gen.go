// Code generated by "make api"; DO NOT EDIT.
package api

import (
	"encoding/json"

	"github.com/fatih/structs"

	"github.com/hashicorp/watchtower/api/internal/strutil"
)

type FieldError struct {
	defaultFields []string

	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

func (s *FieldError) SetDefault(key string) {
	s.defaultFields = strutil.AppendIfMissing(s.defaultFields, key)
}

func (s *FieldError) UnsetDefault(key string) {
	s.defaultFields = strutil.StrListDelete(s.defaultFields, key)
}

func (s FieldError) MarshalJSON() ([]byte, error) {
	m := structs.Map(s)
	if m == nil {
		m = make(map[string]interface{})
	}
	for _, k := range s.defaultFields {
		m[k] = nil
	}
	return json.Marshal(m)
}
