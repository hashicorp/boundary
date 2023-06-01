// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package boundary_plugin_assets

import (
	"embed"
	"io/fs"
)

const contentDir = "assets"

// content is our static web server content.
//
//go:embed assets
var content embed.FS

func FileSystem() fs.FS {
	// Remove the root
	f, err := fs.Sub(content, contentDir)
	if err != nil {
		panic(err)
	}
	return f
}
