package sshprivatekey

import "github.com/hashicorp/boundary/internal/credential"

type (
	data map[string]any

	// extractFunc attempts to extract the username and private key
	// from sd using the provided attribute names, using a known
	// Vault data response format.
	extractFunc func(sd data, usernameAttr, privateKeyAttr string) (string, credential.PrivateKey)
)

// Extract attempts to extract the values of the username and private key
// stored within the provided data using the given attribute names.
//
// Extract does not return partial results, i.e. if one of the attributes
// were extracted but not the other ("", nil) will be returned.
func Extract(d data, usernameAttr, privateKeyAttr string) (string, credential.PrivateKey) {
	for _, f := range []extractFunc{
		defaultExtract,
		kv2Extract,
	} {
		username, privateKey := f(d, usernameAttr, privateKeyAttr)
		if username != "" && privateKey != nil {
			// got valid username and privateKey from secret
			return username, privateKey
		}
	}

	return "", nil
}

// defaultExtract looks for the usernameAttr and privateKeyAttr in the data map
func defaultExtract(sd data, usernameAttr, privateKeyAttr string) (username string, privateKey credential.PrivateKey) {
	if u, ok := sd[usernameAttr]; ok {
		if u, ok := u.(string); ok {
			username = u
		}
	}
	if p, ok := sd[privateKeyAttr]; ok {
		if p, ok := p.(string); ok {
			privateKey = credential.PrivateKey(p)
		}
	}

	return username, privateKey
}

// kv2Extract looks for the the usernameAttr and privateKeyAttr in the embedded
// 'data' field within the data map.
//
// Additionaly it validates the data is in the expected KV-v2 format:
// {
// 	"data": {},
//	"metadata: {}
// }
// If the format does not match, it returns ("", ""). See:
// https://www.vaultproject.io/api/secret/kv/kv-v2#sample-response-1
func kv2Extract(d data, usernameAttr, privateKeyAttr string) (username string, privateKey credential.PrivateKey) {
	var data, metadata map[string]any
	for k, v := range d {
		switch k {
		case "data":
			var ok bool
			if data, ok = v.(map[string]any); !ok {
				// data field should be of type map[string]any in KV-v2
				return "", nil
			}
		case "metadata":
			var ok bool
			if metadata, ok = v.(map[string]any); !ok {
				// metadata field should be of type map[string]any in KV-v2
				return "", nil
			}
		default:
			// secretData contains a non valid KV-v2 top level field
			return "", nil
		}
	}
	if data == nil || metadata == nil {
		// missing required KV-v2 field
		return "", nil
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

	return username, privateKey
}
