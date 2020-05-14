package migrations

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
)

// migrationDriver satisfies the remaining need of the Driver interface, since
// the package uses PartialDriver under the hood
type migrationDriver struct {
	dialect string
}

// Open returns the given "file"
func (m *migrationDriver) Open(name string) (http.File, error) {
	return newFakeFile(m.dialect, name)
}

// NewMigrationSource creates a source.Driver using httpfs with the given dialect
func NewMigrationSource(dialect string) (source.Driver, error) {
	switch dialect {
	case "postgres":
	default:
		return nil, fmt.Errorf("unknown migrations dialect %s", dialect)
	}
	return httpfs.New(&migrationDriver{dialect}, "migrations")
}

// fakeFile is used to satisfy the http.File interface
type fakeFile struct {
	name    string
	bytes   []byte
	reader  *bytes.Reader
	dialect string
}

func newFakeFile(dialect string, name string) (*fakeFile, error) {
	var ff *fakeFile
	switch dialect {
	case "postgres":
		ff = postgresMigrations[name]
	}
	if ff == nil {
		return nil, os.ErrNotExist
	}
	ff.name = strings.TrimPrefix(name, "migrations/")
	ff.reader = bytes.NewReader(ff.bytes)
	ff.dialect = dialect
	return ff, nil
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
	// Get the right map
	var migrationsMap map[string]*fakeFile
	switch f.dialect {
	case "postgres":
		migrationsMap = postgresMigrations
	default:
		return nil, fmt.Errorf("unknown database dialect %s", f.dialect)
	}

	// Sort the keys. May not be necessary but feels nice.
	keys := make([]string, 0, len(migrationsMap))
	for k := range migrationsMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Create the slice of fileinfo objects to return
	ret := make([]os.FileInfo, 0, len(migrationsMap))
	for i, v := range keys {
		// We need "migrations" in the map for the initial Open call but we
		// should not return it as part of the "directory"'s "files".
		if v == "migrations" {
			continue
		}
		stat, err := migrationsMap[v].Stat()
		if err != nil {
			return nil, err
		}
		ret = append(ret, stat)
		if count > 0 && count == i {
			break
		}
	}
	return ret, nil
}

// Stat returns a new fakeFileInfo object with the necessary bits
func (f *fakeFile) Stat() (os.FileInfo, error) {
	return &fakeFileInfo{
		name: f.name,
		size: int64(len(f.bytes)),
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
