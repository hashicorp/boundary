package plugins

import (
	"embed"
	"io/fs"
)

const contentDir = "assets/linux_386"

// content is our static web server content.
//go:embed assets/linux_386
var content embed.FS

func FileSystem() fs.FS {
	// Remove the root
	f, err := fs.Sub(content, contentDir)
	if err != nil {
		panic(err)
	}
	return f
}
