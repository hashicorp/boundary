// Package dburl provides a standard, [net/url.URL] style mechanism for parsing
// and opening SQL database connection strings for Go. Provides standardized
// way to parse and open [URL]'s for popular databases PostgreSQL, MySQL, SQLite3,
// Oracle Database, Microsoft SQL Server, in addition to most other SQL
// databases with a publicly available Go driver.
//
// See the [package documentation README section] for more details.
//
// [package documentation README section]: https://pkg.go.dev/github.com/xo/dburl#section-readme
package dburl

import (
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// ResolveSchemeType is a configuration setting to open paths on disk using
// [SchemeType], [Stat], and [OpenFile]. Set this to false in an `init()` func
// in order to disable this behavior.
var ResolveSchemeType = true

// Open takes a URL string, also known as a DSN, in the form of
// "protocol+transport://user:pass@host/dbname?option1=a&option2=b" and opens a
// standard [sql.DB] connection.
//
// See [Parse] for information on formatting URL strings to work properly with Open.
func Open(urlstr string) (*sql.DB, error) {
	u, err := Parse(urlstr)
	if err != nil {
		return nil, err
	}
	driver := u.Driver
	if u.GoDriver != "" {
		driver = u.GoDriver
	}
	return sql.Open(driver, u.DSN)
}

// OpenMap takes a map of URL components and opens a standard [sql.DB] connection.
//
// See [BuildURL] for information on the recognized map components.
func OpenMap(components map[string]interface{}) (*sql.DB, error) {
	urlstr, err := BuildURL(components)
	if err != nil {
		return nil, err
	}
	return Open(urlstr)
}

// URL wraps the standard [net/url.URL] type, adding OriginalScheme, Transport,
// Driver, Unaliased, and DSN strings.
type URL struct {
	// URL is the base [net/url.URL].
	url.URL
	// OriginalScheme is the original parsed scheme (ie, "sq", "mysql+unix", "sap", etc).
	OriginalScheme string
	// Transport is the specified transport protocol (ie, "tcp", "udp",
	// "unix", ...), if provided.
	Transport string
	// Driver is the non-aliased SQL driver name that should be used in a call
	// to [sql.Open].
	Driver string
	// GoDriver is the Go SQL driver name to use when opening a connection to
	// the database. Used by Microsoft SQL Server's azuresql:// URLs, as the
	// wire-compatible alias style uses a different syntax style.
	GoDriver string
	// UnaliasedDriver is the unaliased driver name.
	UnaliasedDriver string
	// DSN is the built connection "data source name" that can be used in a
	// call to [sql.Open].
	DSN string
	// hostPortDB will be set by Gen*() funcs after determining the host, port,
	// database.
	//
	// When empty, indicates that these values are not special, and can be
	// retrieved as the host, port, and path[1:] as usual.
	hostPortDB []string
}

// Parse parses a URL string, similar to the standard [net/url.Parse].
//
// Handles parsing OriginalScheme, Transport, Driver, Unaliased, and DSN
// fields.
//
// Note: if the URL has a Opaque component (ie, URLs not specified as
// "scheme://" but "scheme:"), and the database scheme does not support opaque
// components, Parse will attempt to re-process the URL as "scheme://<opaque>".
func Parse(urlstr string) (*URL, error) {
	// parse url
	v, err := url.Parse(urlstr)
	switch {
	case err != nil:
		return nil, err
	case v.Scheme == "":
		if ResolveSchemeType {
			if typ, err := SchemeType(urlstr); err == nil {
				return Parse(typ + ":" + urlstr)
			}
		}
		return nil, ErrInvalidDatabaseScheme
	}
	// create url
	u := &URL{
		URL:            *v,
		OriginalScheme: urlstr[:len(v.Scheme)],
		Transport:      "tcp",
	}
	// check for +transport in scheme
	var checkTransport bool
	if i := strings.IndexRune(u.Scheme, '+'); i != -1 {
		u.Transport = urlstr[i+1 : len(v.Scheme)]
		u.Scheme = u.Scheme[:i]
		checkTransport = true
	}
	// get dsn generator
	scheme, ok := schemeMap[u.Scheme]
	switch {
	case !ok:
		return nil, ErrUnknownDatabaseScheme
	case scheme.Driver == "file":
		// determine scheme for file
		s := u.opaqueOrPath()
		switch {
		case u.Transport != "tcp", strings.Index(u.OriginalScheme, "+") != -1:
			return nil, ErrInvalidTransportProtocol
		case s == "":
			return nil, ErrMissingPath
		case ResolveSchemeType:
			if typ, err := SchemeType(s); err == nil {
				return Parse(typ + "://" + u.buildOpaque())
			}
		}
		return nil, ErrUnknownFileExtension
	case !scheme.Opaque && u.Opaque != "":
		// if scheme does not understand opaque URLs, retry parsing after
		// building fully qualified URL
		return Parse(u.OriginalScheme + "://" + u.buildOpaque())
	case scheme.Opaque && u.Opaque == "":
		// force Opaque
		u.Opaque, u.Host, u.Path, u.RawPath = u.Host+u.Path, "", "", ""
	case u.Host == ".", u.Host == "" && strings.TrimPrefix(u.Path, "/") != "":
		// force unix proto
		u.Transport = "unix"
	}
	// check transport
	if checkTransport || u.Transport != "tcp" {
		switch {
		case scheme.Transport == TransportNone:
			return nil, ErrInvalidTransportProtocol
		case scheme.Transport&TransportAny != 0 && u.Transport != "",
			scheme.Transport&TransportTCP != 0 && u.Transport == "tcp",
			scheme.Transport&TransportUDP != 0 && u.Transport == "udp",
			scheme.Transport&TransportUnix != 0 && u.Transport == "unix":
		default:
			return nil, ErrInvalidTransportProtocol
		}
	}
	// set driver
	u.Driver, u.UnaliasedDriver = scheme.Driver, scheme.Driver
	if scheme.Override != "" {
		u.Driver = scheme.Override
	}
	// generate dsn
	if u.DSN, u.GoDriver, err = scheme.Generator(u); err != nil {
		return nil, err
	}
	return u, nil
}

// FromMap creates a [URL] using the mapped components.
//
// Recognized components are:
//
//	protocol, proto, scheme
//	transport
//	username, user
//	password, pass
//	hostname, host
//	port
//	path, file, opaque
//	database, dbname, db
//	instance
//	parameters, params, options, opts, query, q
//
// See [BuildURL] for more information.
func FromMap(components map[string]interface{}) (*URL, error) {
	urlstr, err := BuildURL(components)
	if err != nil {
		return nil, err
	}
	return Parse(urlstr)
}

// String satisfies the [fmt.Stringer] interface.
func (u *URL) String() string {
	p := &url.URL{
		Scheme:   u.OriginalScheme,
		Opaque:   u.Opaque,
		User:     u.User,
		Host:     u.Host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
	}
	return p.String()
}

// Short provides a short description of the user, host, and database.
func (u *URL) Short() string {
	if u.Scheme == "" {
		return ""
	}
	s := schemeMap[u.Scheme].Aliases[0]
	if u.Scheme == "odbc" || u.Scheme == "oleodbc" {
		n := u.Transport
		if v, ok := schemeMap[n]; ok {
			n = v.Aliases[0]
		}
		s += "+" + n
	} else if u.Transport != "tcp" {
		s += "+" + u.Transport
	}
	s += ":"
	if u.User != nil {
		if n := u.User.Username(); n != "" {
			s += n + "@"
		}
	}
	if u.Host != "" {
		s += u.Host
	}
	if u.Path != "" && u.Path != "/" {
		s += u.Path
	}
	if u.Opaque != "" {
		s += u.Opaque
	}
	return s
}

// Normalize returns the driver, host, port, database, and user name of a URL,
// joined with sep, populating blank fields with empty.
func (u *URL) Normalize(sep, empty string, cut int) string {
	s := []string{u.UnaliasedDriver, "", "", "", ""}
	if u.Transport != "tcp" && u.Transport != "unix" {
		s[0] += "+" + u.Transport
	}
	// set host port dbname fields
	if u.hostPortDB == nil {
		if u.Opaque != "" {
			u.hostPortDB = []string{u.Opaque, "", ""}
		} else {
			u.hostPortDB = []string{u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")}
		}
	}
	copy(s[1:], u.hostPortDB)
	// set user
	if u.User != nil {
		s[4] = u.User.Username()
	}
	// replace blank entries ...
	for i := 0; i < len(s); i++ {
		if s[i] == "" {
			s[i] = empty
		}
	}
	if cut > 0 {
		// cut to only populated fields
		i := len(s) - 1
		for ; i > cut; i-- {
			if s[i] != "" {
				break
			}
		}
		s = s[:i]
	}
	return strings.Join(s, sep)
}

// buildOpaque builds a opaque path.
func (u *URL) buildOpaque() string {
	var up string
	if u.User != nil {
		up = u.User.String() + "@"
	}
	var q string
	if u.RawQuery != "" {
		q = "?" + u.RawQuery
	}
	var f string
	if u.Fragment != "" {
		f = "#" + u.Fragment
	}
	return up + u.opaqueOrPath() + q + f
}

// opaqueOrPath returns the opaque or path value.
func (u *URL) opaqueOrPath() string {
	if u.Opaque != "" {
		return u.Opaque
	}
	return u.Path
}

// SchemeType returns the scheme type for a path.
func SchemeType(name string) (string, error) {
	// try to resolve the path on unix systems
	if runtime.GOOS != "windows" {
		if typ, ok := resolveType(name); ok {
			return typ, nil
		}
	}
	if f, err := OpenFile(name); err == nil {
		defer f.Close()
		// file exists, match header
		buf := make([]byte, 64)
		if n, _ := f.Read(buf); n == 0 {
			return "sqlite3", nil
		}
		for _, typ := range fileTypes {
			if typ.f(buf) {
				return typ.driver, nil
			}
		}
		return "", ErrUnknownFileHeader
	}
	// doesn't exist, match file extension
	ext := filepath.Ext(name)
	for _, typ := range fileTypes {
		if typ.ext.MatchString(ext) {
			return typ.driver, nil
		}
	}
	return "", ErrUnknownFileExtension
}

// Error is an error.
type Error string

// Error satisfies the error interface.
func (err Error) Error() string {
	return string(err)
}

// Error values.
const (
	// ErrInvalidDatabaseScheme is the invalid database scheme error.
	ErrInvalidDatabaseScheme Error = "invalid database scheme"
	// ErrUnknownDatabaseScheme is the unknown database type error.
	ErrUnknownDatabaseScheme Error = "unknown database scheme"
	// ErrUnknownFileHeader is the unknown file header error.
	ErrUnknownFileHeader Error = "unknown file header"
	// ErrUnknownFileExtension is the unknown file extension error.
	ErrUnknownFileExtension Error = "unknown file extension"
	// ErrInvalidTransportProtocol is the invalid transport protocol error.
	ErrInvalidTransportProtocol Error = "invalid transport protocol"
	// ErrRelativePathNotSupported is the relative paths not supported error.
	ErrRelativePathNotSupported Error = "relative path not supported"
	// ErrMissingHost is the missing host error.
	ErrMissingHost Error = "missing host"
	// ErrMissingPath is the missing path error.
	ErrMissingPath Error = "missing path"
	// ErrMissingUser is the missing user error.
	ErrMissingUser Error = "missing user"
	// ErrInvalidQuery is the invalid query error.
	ErrInvalidQuery Error = "invalid query"
)

// Stat is the default stat func.
//
// Used internally to stat files, and used when generating the DSNs for
// postgres://, mysql://, file:// schemes, and opaque [URL]'s.
var Stat = func(name string) (fs.FileInfo, error) {
	return fs.Stat(os.DirFS(filepath.Dir(name)), filepath.Base(name))
}

// OpenFile is the default open file func.
//
// Used internally to read file headers.
var OpenFile = func(name string) (fs.File, error) {
	f, err := os.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// BuildURL creates a dsn using the mapped components.
//
// Recognized components are:
//
//	protocol, proto, scheme
//	transport
//	username, user
//	password, pass
//	hostname, host
//	port
//	path, file, opaque
//	database, dbname, db
//	instance
//	parameters, params, options, opts, query, q
//
// See [BuildURL] for more information.
func BuildURL(components map[string]interface{}) (string, error) {
	if components == nil {
		return "", ErrInvalidDatabaseScheme
	}
	var urlstr string
	if proto, ok := getComponent(components, "protocol", "proto", "scheme"); ok {
		if transport, ok := getComponent(components, "transport"); ok {
			proto += "+" + transport
		}
		urlstr = proto + ":"
	}
	if host, ok := getComponent(components, "hostname", "host"); ok {
		hostinfo := url.QueryEscape(host)
		if port, ok := getComponent(components, "port"); ok {
			hostinfo += ":" + port
		}
		var userinfo string
		if user, ok := getComponent(components, "username", "user"); ok {
			userinfo += url.QueryEscape(user)
			if pass, ok := getComponent(components, "password", "pass"); ok {
				userinfo += ":" + url.QueryEscape(pass)
			}
			hostinfo = userinfo + "@" + hostinfo
		}
		urlstr += "//" + hostinfo
	}
	if pathstr, ok := getComponent(components, "path", "file", "opaque"); ok {
		if urlstr == "" {
			urlstr += "file:"
		}
		urlstr += pathstr
	} else {
		var v []string
		if instance, ok := getComponent(components, "instance"); ok {
			v = append(v, url.PathEscape(instance))
		}
		if dbname, ok := getComponent(components, "database", "dbname", "db"); ok {
			v = append(v, url.PathEscape(dbname))
		}
		if len(v) != 0 {
			if s := path.Join(v...); s != "" {
				urlstr += "/" + s
			}
		}
	}
	if v, ok := getFirst(components, "parameters", "params", "options", "opts", "query", "q"); ok {
		switch z := v.(type) {
		case string:
			if z != "" {
				urlstr += "?" + z
			}
		case map[string]interface{}:
			q := url.Values{}
			for k, v := range z {
				q.Set(k, fmt.Sprintf("%v", v))
			}
			if s := q.Encode(); s != "" {
				urlstr += "?" + s
			}
		default:
			return "", ErrInvalidQuery
		}
	}
	return urlstr, nil
}

// resolveType tries to resolve a path to a Unix domain socket or directory.
func resolveType(s string) (string, bool) {
	if i := strings.LastIndex(s, "?"); i != -1 {
		if _, err := Stat(s[:i]); err == nil {
			s = s[:i]
		}
	}
	dir := s
	for dir != "" && dir != "/" && dir != "." {
		// chop off :4444 port
		i, j := strings.LastIndex(dir, ":"), strings.LastIndex(dir, "/")
		if i != -1 && i > j {
			dir = dir[:i]
		}
		switch fi, err := Stat(dir); {
		case err == nil && fi.IsDir():
			return "postgres", true
		case err == nil && fi.Mode()&fs.ModeSocket != 0:
			return "mysql", true
		case err == nil:
			return "", false
		}
		if j != -1 {
			dir = dir[:j]
		} else {
			dir = ""
		}
	}
	return "", false
}

// resolveSocket tries to resolve a path to a Unix domain socket based on the
// form "/path/to/socket/dbname" returning either the original path and the
// empty string, or the components "/path/to/socket" and "dbname", when
// /path/to/socket/dbname is reported by Stat as a socket.
func resolveSocket(s string) (string, string) {
	dir, dbname := s, ""
	for dir != "" && dir != "/" && dir != "." {
		if mode(dir)&fs.ModeSocket != 0 {
			return dir, dbname
		}
		dir, dbname = path.Dir(dir), path.Base(dir)
	}
	return s, ""
}

// resolveDir resolves a directory with a :port list.
func resolveDir(s string) (string, string, string) {
	dir := s
	for dir != "" && dir != "/" && dir != "." {
		port := ""
		i, j := strings.LastIndex(dir, ":"), strings.LastIndex(dir, "/")
		if i != -1 && i > j {
			port, dir = dir[i+1:], dir[:i]
		}
		if mode(dir)&fs.ModeDir != 0 {
			dbname := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(s, dir), ":"+port), "/")
			return dir, port, dbname
		}
		if j != -1 {
			dir = dir[:j]
		} else {
			dir = ""
		}
	}
	return s, "", ""
}

// mode returns the mode of the path.
func mode(s string) os.FileMode {
	if fi, err := Stat(s); err == nil {
		return fi.Mode()
	}
	return 0
}

// getComponent returns the first defined component in the map.
func getComponent(m map[string]interface{}, v ...string) (string, bool) {
	if z, ok := getFirst(m, v...); ok {
		str := fmt.Sprintf("%v", z)
		return str, str != ""

	}
	return "", false
}

// getFirst returns the first value in the map.
func getFirst(m map[string]interface{}, v ...string) (interface{}, bool) {
	for _, s := range v {
		if z, ok := m[s]; ok {
			return z, ok
		}
	}
	return nil, false
}
