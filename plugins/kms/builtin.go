package kms_plugin_assets

import (
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
)

func BuiltinKmsPlugins() map[string]pluginutil.InmemCreationFunc {
	return map[string]pluginutil.InmemCreationFunc{
		"aead": func() (interface{}, error) {
			return aead.NewWrapper(), nil
		},
	}
}
