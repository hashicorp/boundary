// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package usernamepassword

import (
	"strings"

	"github.com/mitchellh/pointerstructure"
)

type (
	data map[string]any

	// extractFunc attempts to extract the username and password
	// from sd using the provided attribute names, using a known
	// Vault data response format.
	extractFunc func(sd data, usernameAttr, passwordAttr string) (string, string)
)

// Extract attempts to extract the values of the username and password
// stored within the provided data using the given attribute names.
//
// Extract does not return partial results, i.e. if one of the attributes
// were extracted but not the other ("", "") will be returned.
func Extract(d data, usernameAttr, passwordAttr string) (string, string) {
	for _, f := range []extractFunc{
		defaultExtract,
		kv2Extract,
	} {
		username, password := f(d, usernameAttr, passwordAttr)
		if username != "" && password != "" {
			// got valid username and password from secret
			return username, password
		}
	}

	return "", ""
}

// defaultExtract looks for the usernameAttr and passwordAttr in the data map
func defaultExtract(sd data, usernameAttr, passwordAttr string) (username string, password string) {
	if sd == nil {
		// nothing to do return early
		return "", ""
	}

	var u any
	switch {
	case strings.HasPrefix(usernameAttr, "/"):
		var err error
		u, err = pointerstructure.Get(sd, usernameAttr)
		if err != nil {
			return "", ""
		}

	default:
		u = sd[usernameAttr]
	}
	if u, ok := u.(string); ok {
		username = u
	}

	var p any
	switch {
	case strings.HasPrefix(passwordAttr, "/"):
		var err error
		p, err = pointerstructure.Get(sd, passwordAttr)
		if err != nil {
			return "", ""
		}

	default:
		p = sd[passwordAttr]
	}

	if p, ok := p.(string); ok {
		password = p
	}

	return username, password
}

// kv2Extract looks for the the usernameAttr and passwordAttr in the embedded
// 'data' field within the data map.
//
// Additionally it validates the data is in the expected KV-v2 format:
//
//	{
//		"data": {},
//		"metadata: {}
//	}
//
// If the format does not match, it returns ("", ""). See:
// https://www.vaultproject.io/api/secret/kv/kv-v2#sample-response-1
func kv2Extract(sd data, usernameAttr, passwordAttr string) (username string, password string) {
	if sd == nil {
		// nothing to do return early
		return "", ""
	}

	var data, metadata map[string]any
	for k, v := range sd {
		switch k {
		case "data":
			var ok bool
			if data, ok = v.(map[string]any); !ok {
				// data field should be of type map[string]interface{} in KV-v2
				return "", ""
			}
		case "metadata":
			var ok bool
			if metadata, ok = v.(map[string]any); !ok {
				// metadata field should be of type map[string]interface{} in KV-v2
				return "", ""
			}
		default:
			// secretData contains a non valid KV-v2 top level field
			return "", ""
		}
	}
	if data == nil || metadata == nil {
		// missing required KV-v2 field
		return "", ""
	}

	if u, ok := data[usernameAttr]; ok {
		if u, ok := u.(string); ok {
			username = u
		}
	}
	if p, ok := data[passwordAttr]; ok {
		if p, ok := p.(string); ok {
			password = p
		}
	}

	return username, password
}
