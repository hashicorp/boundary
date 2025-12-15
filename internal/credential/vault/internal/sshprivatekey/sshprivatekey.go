// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sshprivatekey

import (
	"strings"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/mitchellh/pointerstructure"
)

type (
	data map[string]any

	// extractFunc attempts to extract the username and private key
	// from sd using the provided attribute names, using a known
	// Vault data response format.
	extractFunc func(sd data, usernameAttr, privateKeyAttr, passphraseAttr string) (string, credential.PrivateKey, []byte)
)

// Extract attempts to extract the values of the username, private key and optional
// passphrase stored within the provided data using the given attribute names.
//
// Extract does not return partial results, i.e. if one of the attributes
// were extracted but not the other ("", nil) will be returned.
func Extract(d data, usernameAttr, privateKeyAttr, passphraseAttr string) (string, credential.PrivateKey, []byte) {
	for _, f := range []extractFunc{
		defaultExtract,
		kv2Extract,
	} {
		username, privateKey, passphrase := f(d, usernameAttr, privateKeyAttr, passphraseAttr)
		if username != "" && privateKey != nil {
			// got valid username and privateKey from secret
			return username, privateKey, passphrase
		}
	}

	return "", nil, nil
}

// defaultExtract looks for the usernameAttr and privateKeyAttr in the data map
func defaultExtract(sd data, usernameAttr, privateKeyAttr, passphraseAttr string) (
	username string, privateKey credential.PrivateKey, passphrase []byte,
) {
	if sd == nil {
		// nothing to do return early
		return "", nil, nil
	}

	var u any
	switch {
	case strings.HasPrefix(usernameAttr, "/"):
		var err error
		u, err = pointerstructure.Get(sd, usernameAttr)
		if err != nil {
			return "", nil, nil
		}
	default:
		u = sd[usernameAttr]
	}
	if u, ok := u.(string); ok {
		username = u
	}

	var pk any
	switch {
	case strings.HasPrefix(privateKeyAttr, "/"):
		var err error
		pk, err = pointerstructure.Get(sd, privateKeyAttr)
		if err != nil {
			return "", nil, nil
		}
	default:
		pk = sd[privateKeyAttr]
	}
	if p, ok := pk.(string); ok {
		privateKey = credential.PrivateKey(p)
	}

	var pass any
	switch {
	case strings.HasPrefix(passphraseAttr, "/"):
		var err error
		pass, err = pointerstructure.Get(sd, passphraseAttr)
		if err != nil {
			return "", nil, nil
		}
	default:
		pass = sd[passphraseAttr]
	}
	if p, ok := pass.(string); ok {
		passphrase = []byte(p)
	}

	return username, privateKey, passphrase
}

// kv2Extract looks for the the usernameAttr and privateKeyAttr in the embedded
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
func kv2Extract(sd data, usernameAttr, privateKeyAttr, passphraseAttr string) (
	username string, privateKey credential.PrivateKey, passphrase []byte,
) {
	if sd == nil {
		// nothing to do return early
		return "", nil, nil
	}

	var data, metadata map[string]any
	for k, v := range sd {
		switch k {
		case "data":
			var ok bool
			if data, ok = v.(map[string]any); !ok {
				// data field should be of type map[string]any in KV-v2
				return "", nil, nil
			}
		case "metadata":
			var ok bool
			if metadata, ok = v.(map[string]any); !ok {
				// metadata field should be of type map[string]any in KV-v2
				return "", nil, nil
			}
		default:
			// secretData contains a non valid KV-v2 top level field
			return "", nil, nil
		}
	}
	if data == nil || metadata == nil {
		// missing required KV-v2 field
		return "", nil, nil
	}

	if u, ok := data[usernameAttr]; ok {
		if u, ok := u.(string); ok {
			username = u
		}
	}
	if p, ok := data[privateKeyAttr]; ok {
		if p, ok := p.(string); ok {
			privateKey = credential.PrivateKey(p)
		}
	}
	if p, ok := data[passphraseAttr]; ok {
		if p, ok := p.(string); ok {
			passphrase = []byte(p)
		}
	}

	return username, privateKey, passphrase
}
