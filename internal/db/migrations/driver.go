package migrations

import (
	"bytes"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
)

// migrationDriver satisfies the remaining need of the Driver interface, since
// the package uses PartialDriver under the hood. If we want to support more
// than Postgres in the future, we can add a type flag in this struct, and have
// the desired type passed into NewMigrationsSource()
type migrationDriver struct{}

// Open returns the given "file"
func (m *migrationDriver) Open(name string) (http.File, error) {
	ff := postgresMigrations[name]
	if m == nil {
		return nil, os.ErrNotExist
	}
	return ff, nil
}

// NewMigrationSource creates a source.Driver
func NewMigrationSource() (source.Driver, error) {
	return httpfs.New(&migrationDriver{}, "migrations")
}

// fakeFile is used to satisfy the http.File interface
type fakeFile struct {
	name   string
	reader *bytes.Reader
}

func (f *fakeFile) Read(p []byte) (n int, err error) {
	return f.reader.Read(p)
}

func (f *fakeFile) Seek(offset int64, whence int) (int64, error) {
	return f.reader.Seek(offset, whence)
}

func (f *fakeFile) Close() error { return nil }

// Readdir returns os.FileInfo values, in sorted order, and eliding the
// migrations "dir"
func (f *fakeFile) Readdir(count int) ([]os.FileInfo, error) {
	ret := make([]os.FileInfo, 0, len(postgresMigrations))
	keys := make([]string, 0, len(postgresMigrations))
	for k := range postgresMigrations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, v := range keys {
		if v == "migrations" {
			continue
		}
		stat, err := postgresMigrations[v].Stat()
		if err != nil {
			return nil, err
		}
		ret = append(ret, stat)
	}
	return ret, nil
}

func (f *fakeFile) Stat() (os.FileInfo, error) {
	return &fakeFileInfo{
		name: f.name,
		size: int64(f.reader.Len()),
	}, nil
}

// fakeFileInfo satisfies os.FileInfo but represents our fake "files"
type fakeFileInfo struct {
	name string
	size int64
}

func (f *fakeFileInfo) Name() string       { return f.name }
func (f *fakeFileInfo) Size() int64        { return f.size }
func (f *fakeFileInfo) Mode() os.FileMode  { return os.ModePerm }
func (f *fakeFileInfo) ModTime() time.Time { return time.Now() }
func (f *fakeFileInfo) IsDir() bool        { return false }
func (f *fakeFileInfo) Sys() interface{}   { return nil }
