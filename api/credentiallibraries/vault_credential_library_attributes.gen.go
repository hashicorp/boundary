// Code generated by "make api"; DO NOT EDIT.
package credentiallibraries

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type VaultCredentialLibraryAttributes struct {
	Path            string `json:"path,omitempty"`
	HttpMethod      string `json:"http_method,omitempty"`
	HttpRequestBody string `json:"http_request_body,omitempty"`
}

func AttributesMapToVaultCredentialLibraryAttributes(in map[string]interface{}) (*VaultCredentialLibraryAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out VaultCredentialLibraryAttributes
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

func (pt *CredentialLibrary) GetVaultCredentialLibraryAttributes() (*VaultCredentialLibraryAttributes, error) {
	return AttributesMapToVaultCredentialLibraryAttributes(pt.Attributes)
}
