// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build ui
// +build ui

package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

// Sadly we can't embed this into the embed line, but we use it elsewhere
const contentDir = ".tmp/boundary-ui/ui/admin/dist"

// content is our static web server content.
//
//go:embed .tmp/boundary-ui/ui/admin/dist
var content embed.FS

func Handler() http.Handler {
	return http.FileServer(httpFileSystem())
}

func httpFileSystem() http.FileSystem {
	return http.FS(fileSystem())
}

func fileSystem() fs.FS {
	// Remove the root
	f, err := fs.Sub(content, contentDir)
	if err != nil {
		panic(err)
	}
	return f
}
