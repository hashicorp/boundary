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
//go:embed .tmp/boundary-ui/ui/admin/dist
var content embed.FS

func Handler() http.Handler {
	// Remove the root
	f, err := fs.Sub(content, contentDir)
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(f))
}
