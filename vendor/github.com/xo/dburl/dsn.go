package dburl

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
)

// OdbcIgnoreQueryPrefixes are the query prefixes to ignore when generating the
// odbc DSN. Used by GenOdbc
var OdbcIgnoreQueryPrefixes []string

// GenScheme returns a generator that will generate a scheme based on the
// passed scheme DSN.
func GenScheme(scheme string) func(*URL) (string, string, error) {
	return func(u *URL) (string, string, error) {
		z := &url.URL{
			Scheme:   scheme,
			Opaque:   u.Opaque,
			User:     u.User,
			Host:     u.Host,
			Path:     u.Path,
			RawPath:  u.RawPath,
			RawQuery: u.RawQuery,
			Fragment: u.Fragment,
		}
		if z.Host == "" {
			z.Host = "localhost"
		}
		return z.String(), "", nil
	}
}

// GenFromURL returns a func that generates a DSN based on parameters of the
// passed URL.
func GenFromURL(urlstr string) func(*URL) (string, string, error) {
	z, err := url.Parse(urlstr)
	if err != nil {
		panic(err)
	}
	return func(u *URL) (string, string, error) {
		opaque := z.Opaque
		if u.Opaque != "" {
			opaque = u.Opaque
		}
		user := z.User
		if u.User != nil {
			user = u.User
		}
		host, port := z.Hostname(), z.Port()
		if h := u.Hostname(); h != "" {
			host = h
		}
		if p := u.Port(); p != "" {
			port = p
		}
		if port != "" {
			host += ":" + port
		}
		pstr := z.Path
		if u.Path != "" {
			pstr = u.Path
		}
		rawPath := z.RawPath
		if u.RawPath != "" {
			rawPath = u.RawPath
		}
		q := z.Query()
		for k, v := range u.Query() {
			q.Set(k, strings.Join(v, " "))
		}
		fragment := z.Fragment
		if u.Fragment != "" {
			fragment = u.Fragment
		}
		y := &url.URL{
			Scheme:   z.Scheme,
			Opaque:   opaque,
			User:     user,
			Host:     host,
			Path:     pstr,
			RawPath:  rawPath,
			RawQuery: q.Encode(),
			Fragment: fragment,
		}
		return strings.TrimPrefix(y.String(), "truncate://"), "", nil
	}
}

// GenOpaque generates a opaque file path DSN from the passed URL.
func GenOpaque(u *URL) (string, string, error) {
	if u.Opaque == "" {
		return "", "", ErrMissingPath
	}
	return u.Opaque + genQueryOptions(u.Query()), "", nil
}

// GenAdodb generates a adodb DSN from the passed URL.
func GenAdodb(u *URL) (string, string, error) {
	// grab data source
	host, port := u.Hostname(), u.Port()
	dsname, dbname := strings.TrimPrefix(u.Path, "/"), ""
	if dsname == "" {
		dsname = "."
	}
	// check if data source is not a path on disk
	if mode(dsname) == 0 {
		if i := strings.IndexAny(dsname, `\/`); i != -1 {
			dbname = dsname[i+1:]
			dsname = dsname[:i]
		}
	}
	// build q
	q := u.Query()
	q.Set("Provider", host)
	q.Set("Port", port)
	q.Set("Data Source", dsname)
	q.Set("Database", dbname)
	if u.User != nil {
		q.Set("User ID", u.User.Username())
		pass, _ := u.User.Password()
		q.Set("Password", pass)
	}
	if u.hostPortDB == nil {
		n := dsname
		if dbname != "" {
			n += "/" + dbname
		}
		u.hostPortDB = []string{host, port, n}
	}
	return genOptionsOdbc(q, true, nil, OdbcIgnoreQueryPrefixes), "", nil
}

// GenCassandra generates a cassandra DSN from the passed URL.
func GenCassandra(u *URL) (string, string, error) {
	host, port, dbname := "localhost", "9042", strings.TrimPrefix(u.Path, "/")
	if h := u.Hostname(); h != "" {
		host = h
	}
	if p := u.Port(); p != "" {
		port = p
	}
	q := u.Query()
	// add user/pass
	if u.User != nil {
		q.Set("username", u.User.Username())
		if pass, _ := u.User.Password(); pass != "" {
			q.Set("password", pass)
		}
	}
	// add dbname
	if dbname != "" {
		q.Set("keyspace", dbname)
	}
	return host + ":" + port + genQueryOptions(q), "", nil
}

// GenClickhouse generates a clickhouse DSN from the passed URL.
func GenClickhouse(u *URL) (string, string, error) {
	switch strings.ToLower(u.Transport) {
	case "", "tcp":
		return clickhouseTCP(u)
	case "http":
		return clickhouseHTTP(u)
	case "https":
		return clickhouseHTTPS(u)
	}
	return "", "", ErrInvalidTransportProtocol
}

// clickhouse generators.
var (
	clickhouseTCP   = GenFromURL("clickhouse://localhost:9000/")
	clickhouseHTTP  = GenFromURL("http://localhost/")
	clickhouseHTTPS = GenFromURL("https://localhost/")
)

// GenCosmos generates a cosmos DSN from the passed URL.
func GenCosmos(u *URL) (string, string, error) {
	host, port, dbname := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	if port != "" {
		port = ":" + port
	}
	q := u.Query()
	q.Set("AccountEndpoint", "https://"+host+port)
	// add user/pass
	if u.User == nil {
		return "", "", ErrMissingUser
	}
	q.Set("AccountKey", u.User.Username())
	if dbname != "" {
		q.Set("Db", dbname)
	}
	return genOptionsOdbc(q, true, nil, nil), "", nil
}

// GenDatabend generates a databend DSN from the passed URL.
func GenDatabend(u *URL) (string, string, error) {
	if u.Hostname() == "" {
		return "", "", ErrMissingHost
	}
	return u.String(), "", nil
}

// GenDynamo generates a dynamo DSN from the passed URL.
func GenDynamo(u *URL) (string, string, error) {
	var v []string
	if host := u.Hostname(); host != "" {
		v = append(v, "Region="+host)
	}
	if u.User != nil {
		v = append(v, "AkId="+u.User.Username())
		if pass, ok := u.User.Password(); ok {
			v = append(v, "Secret_Key="+pass)
		}
	}
	return strings.Join(v, ";") + genOptions(u.Query(), ";", "=", ";", ",", true, []string{"Region", "Secret_Key", "AkId"}, nil), "", nil
}

// GenDatabricks generates a databricks DSN from the passed URL.
func GenDatabricks(u *URL) (string, string, error) {
	if u.User == nil {
		return "", "", ErrMissingUser
	}
	user := u.User.Username()
	pass, ok := u.User.Password()
	if !ok || pass == "" {
		return "", "", ErrMissingUser
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return "", "", ErrMissingHost
	}
	if port == "" {
		port = "443"
	}
	s := fmt.Sprintf("token:%s@%s.databricks.com:%s/sql/1.0/endpoints/%s", user, pass, port, host)
	return s + genOptions(u.Query(), "?", "=", "&", ",", true, nil, nil), "", nil
}

// GenExasol generates a exasol DSN from the passed URL.
func GenExasol(u *URL) (string, string, error) {
	host, port, dbname := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "8563"
	}
	q := u.Query()
	if dbname != "" {
		q.Set("schema", dbname)
	}
	if u.User != nil {
		q.Set("user", u.User.Username())
		pass, _ := u.User.Password()
		q.Set("password", pass)
	}
	return fmt.Sprintf("exa:%s:%s%s", host, port, genOptions(q, ";", "=", ";", ",", true, nil, nil)), "", nil
}

// GenFirebird generates a firebird DSN from the passed URL.
func GenFirebird(u *URL) (string, string, error) {
	z := &url.URL{
		User:     u.User,
		Host:     u.Host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
	}
	return strings.TrimPrefix(z.String(), "//"), "", nil
}

// GenGodror generates a godror DSN from the passed URL.
func GenGodror(u *URL) (string, string, error) {
	// Easy Connect Naming method enables clients to connect to a database server
	// without any configuration. Clients use a connect string for a simple TCP/IP
	// address, which includes a host name and optional port and service name:
	// CONNECT username[/password]@[//]host[:port][/service_name][:server][/instance_name]
	host, port, service := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	// grab instance name from service name
	var instance string
	if i := strings.LastIndex(service, "/"); i != -1 {
		instance, service = service[i+1:], service[:i]
	}
	// build dsn
	dsn := host
	if port != "" {
		dsn += ":" + port
	}
	if u.User != nil {
		if n := u.User.Username(); n != "" {
			if p, ok := u.User.Password(); ok {
				n += "/" + p
			}
			dsn = n + "@//" + dsn
		}
	}
	if service != "" {
		dsn += "/" + service
	}
	if instance != "" {
		dsn += "/" + instance
	}
	return dsn, "", nil
}

// GenIgnite generates an ignite DSN from the passed URL.
func GenIgnite(u *URL) (string, string, error) {
	host, port, dbname := "localhost", "10800", strings.TrimPrefix(u.Path, "/")
	if h := u.Hostname(); h != "" {
		host = h
	}
	if p := u.Port(); p != "" {
		port = p
	}
	q := u.Query()
	// add user/pass
	if u.User != nil {
		q.Set("username", u.User.Username())
		if pass, _ := u.User.Password(); pass != "" {
			q.Set("password", pass)
		}
	}
	// add dbname
	if dbname != "" {
		dbname = "/" + dbname
	}
	return "tcp://" + host + ":" + port + dbname + genQueryOptions(q), "", nil
}

// GenMymysql generates a mymysql DSN from the passed URL.
func GenMymysql(u *URL) (string, string, error) {
	host, port, dbname := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	// resolve path
	if u.Transport == "unix" {
		if host == "" {
			dbname = "/" + dbname
		}
		host, dbname = resolveSocket(path.Join(host, dbname))
		port = ""
	}
	// save host, port, dbname
	if u.hostPortDB == nil {
		u.hostPortDB = []string{host, port, dbname}
	}
	// if host or proto is not empty
	if u.Transport != "unix" {
		if host == "" {
			host = "localhost"
		}
		if port == "" {
			port = "3306"
		}
	}
	if port != "" {
		port = ":" + port
	}
	// build dsn
	dsn := u.Transport + ":" + host + port
	dsn += genOptions(
		convertOptions(u.Query(), "true", ""),
		",", "=", ",", " ", false,
		nil, nil,
	)
	dsn += "*" + dbname
	if u.User != nil {
		pass, _ := u.User.Password()
		dsn += "/" + u.User.Username() + "/" + pass
	} else if strings.HasSuffix(dsn, "*") {
		dsn += "//"
	}
	return dsn, "", nil
}

// GenMysql generates a mysql DSN from the passed URL.
func GenMysql(u *URL) (string, string, error) {
	host, port, dbname := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	// build dsn
	var dsn string
	if u.User != nil {
		if n := u.User.Username(); n != "" {
			if p, ok := u.User.Password(); ok {
				n += ":" + p
			}
			dsn += n + "@"
		}
	}
	// resolve path
	if u.Transport == "unix" {
		if host == "" {
			dbname = "/" + dbname
		}
		host, dbname = resolveSocket(path.Join(host, dbname))
		port = ""
	}
	// save host, port, dbname
	if u.hostPortDB == nil {
		u.hostPortDB = []string{host, port, dbname}
	}
	// if host or proto is not empty
	if u.Transport != "unix" {
		if host == "" {
			host = "localhost"
		}
		if port == "" {
			port = "3306"
		}
	}
	if port != "" {
		port = ":" + port
	}
	// add proto and database
	dsn += u.Transport + "(" + host + port + ")" + "/" + dbname
	return dsn + genQueryOptions(u.Query()), "", nil
}

// GenOdbc generates a odbc DSN from the passed URL.
func GenOdbc(u *URL) (string, string, error) {
	// save host, port, dbname
	host, port, dbname := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	if u.hostPortDB == nil {
		u.hostPortDB = []string{host, port, dbname}
	}
	// build q
	q := u.Query()
	q.Set("Driver", "{"+strings.Replace(u.Transport, "+", " ", -1)+"}")
	q.Set("Server", host)
	if port == "" {
		proto := strings.ToLower(u.Transport)
		switch {
		case strings.Contains(proto, "mysql"):
			q.Set("Port", "3306")
		case strings.Contains(proto, "postgres"):
			q.Set("Port", "5432")
		case strings.Contains(proto, "db2") || strings.Contains(proto, "ibm"):
			q.Set("ServiceName", "50000")
		default:
			q.Set("Port", "1433")
		}
	} else {
		q.Set("Port", port)
	}
	q.Set("Database", dbname)
	// add user/pass
	if u.User != nil {
		q.Set("UID", u.User.Username())
		p, _ := u.User.Password()
		q.Set("PWD", p)
	}
	return genOptionsOdbc(q, true, nil, OdbcIgnoreQueryPrefixes), "", nil
}

// GenOleodbc generates a oleodbc DSN from the passed URL.
func GenOleodbc(u *URL) (string, string, error) {
	props, _, err := GenOdbc(u)
	if err != nil {
		return "", "", nil
	}
	return `Provider=MSDASQL.1;Extended Properties="` + props + `"`, "", nil
}

// GenPostgres generates a postgres DSN from the passed URL.
func GenPostgres(u *URL) (string, string, error) {
	host, port, dbname := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	if host == "." {
		return "", "", ErrRelativePathNotSupported
	}
	// resolve path
	if u.Transport == "unix" {
		if host == "" {
			dbname = "/" + dbname
		}
		host, port, dbname = resolveDir(path.Join(host, dbname))
	}
	// build q
	q := u.Query()
	q.Set("host", host)
	q.Set("port", port)
	q.Set("dbname", dbname)
	// add user/pass
	if u.User != nil {
		q.Set("user", u.User.Username())
		pass, _ := u.User.Password()
		q.Set("password", pass)
	}
	// save host, port, dbname
	if u.hostPortDB == nil {
		u.hostPortDB = []string{host, port, dbname}
	}
	return genOptions(q, "", "=", " ", ",", true, nil, nil), "", nil
}

// GenPresto generates a presto DSN from the passed URL.
func GenPresto(u *URL) (string, string, error) {
	z := &url.URL{
		Scheme:   "http",
		Opaque:   u.Opaque,
		User:     u.User,
		Host:     u.Host,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
	}
	// change to https
	if strings.HasSuffix(u.OriginalScheme, "s") {
		z.Scheme = "https"
	}
	// force user
	if z.User == nil {
		z.User = url.User("user")
	}
	// force host
	if z.Host == "" {
		z.Host = "localhost"
	}
	// force port
	if z.Port() == "" {
		if z.Scheme == "http" {
			z.Host += ":8080"
		} else if z.Scheme == "https" {
			z.Host += ":8443"
		}
	}
	// add parameters
	q := z.Query()
	dbname, schema := strings.TrimPrefix(u.Path, "/"), ""
	if dbname == "" {
		dbname = "default"
	} else if i := strings.Index(dbname, "/"); i != -1 {
		schema, dbname = dbname[i+1:], dbname[:i]
	}
	q.Set("catalog", dbname)
	if schema != "" {
		q.Set("schema", schema)
	}
	z.RawQuery = q.Encode()
	return z.String(), "", nil
}

// GenSnowflake generates a snowflake DSN from the passed URL.
func GenSnowflake(u *URL) (string, string, error) {
	host, port, dbname := u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
	if host == "" {
		return "", "", ErrMissingHost
	}
	if port != "" {
		port = ":" + port
	}
	// add user/pass
	if u.User == nil {
		return "", "", ErrMissingUser
	}
	user := u.User.Username()
	if pass, _ := u.User.Password(); pass != "" {
		user += ":" + pass
	}
	return user + "@" + host + port + "/" + dbname + genQueryOptions(u.Query()), "", nil
}

// GenSpanner generates a spanner DSN from the passed URL.
func GenSpanner(u *URL) (string, string, error) {
	project, instance, dbname := u.Hostname(), "", strings.TrimPrefix(u.Path, "/")
	if project == "" {
		return "", "", ErrMissingHost
	}
	i := strings.Index(dbname, "/")
	if i == -1 {
		return "", "", ErrMissingPath
	}
	instance, dbname = dbname[:i], dbname[i+1:]
	if instance == "" || dbname == "" {
		return "", "", ErrMissingPath
	}
	return fmt.Sprintf(`projects/%s/instances/%s/databases/%s`, project, instance, dbname), "", nil
}

// GenSqlserver generates a sqlserver DSN from the passed URL.
func GenSqlserver(u *URL) (string, string, error) {
	z := &url.URL{
		Scheme:   "sqlserver",
		Opaque:   u.Opaque,
		User:     u.User,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
	}
	if z.Host == "" {
		z.Host = "localhost"
	}
	driver := "sqlserver"
	if strings.Contains(strings.ToLower(u.Scheme), "azuresql") ||
		u.Query().Get("fedauth") != "" {
		driver = "azuresql"
	}
	v := strings.Split(strings.TrimPrefix(z.Path, "/"), "/")
	if n, q := len(v), z.Query(); !q.Has("database") && n != 0 && len(v[0]) != 0 {
		q.Set("database", v[n-1])
		z.Path, z.RawQuery = "/"+strings.Join(v[:n-1], "/"), q.Encode()
	}
	return z.String(), driver, nil
}

// GenTableStore generates a tablestore DSN from the passed URL.
func GenTableStore(u *URL) (string, string, error) {
	var transport string
	splits := strings.Split(u.OriginalScheme, "+")
	if len(splits) == 0 {
		return "", "", ErrInvalidDatabaseScheme
	} else if len(splits) == 1 || splits[1] == "https" {
		transport = "https"
	} else if splits[1] == "http" {
		transport = "http"
	} else {
		return "", "", ErrInvalidTransportProtocol
	}
	z := &url.URL{
		Scheme:   transport,
		Opaque:   u.Opaque,
		User:     u.User,
		Host:     u.Host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
	}
	return z.String(), "", nil
}

// GenVoltdb generates a voltdb DSN from the passed URL.
func GenVoltdb(u *URL) (string, string, error) {
	host, port := "localhost", "21212"
	if h := u.Hostname(); h != "" {
		host = h
	}
	if p := u.Port(); p != "" {
		port = p
	}
	return host + ":" + port, "", nil
}

// GenYDB generates a ydb dsn from the passed URL.
func GenYDB(u *URL) (string, string, error) {
	scheme, host, port := "grpc", "localhost", "2136"
	if strings.HasSuffix(strings.ToLower(u.OriginalScheme), "s") {
		scheme, port = "grpcs", "2135"
	}
	if h := u.Hostname(); h != "" {
		host = h
	}
	if p := u.Port(); p != "" {
		port = p
	}
	var userpass string
	if u.User != nil {
		userpass = u.User.String() + "@"
	}
	s := scheme + "://" + userpass + host + ":" + port + "/" + strings.TrimPrefix(u.Path, "/")
	return s + genOptions(u.Query(), "?", "=", "&", ",", true, nil, nil), "", nil
}

// convertOptions converts an option value based on name, value pairs.
func convertOptions(q url.Values, pairs ...string) url.Values {
	n := make(url.Values)
	for k, v := range q {
		x := make([]string, len(v))
		for i, z := range v {
			for j := 0; j < len(pairs); j += 2 {
				if pairs[j] == z {
					z = pairs[j+1]
				}
			}
			x[i] = z
		}
		n[k] = x
	}
	return n
}

// genQueryOptions generates standard query options.
func genQueryOptions(q url.Values) string {
	if s := q.Encode(); s != "" {
		return "?" + s
	}
	return ""
}

// genOptionsOdbc is a util wrapper around genOptions that uses the fixed
// settings for ODBC style connection strings.
func genOptionsOdbc(q url.Values, skipWhenEmpty bool, ignore, ignorePrefixes []string) string {
	return genOptions(q, "", "=", ";", ",", skipWhenEmpty, ignore, ignorePrefixes)
}

// genOptions takes URL values and generates options, joining together with
// joiner, and separated by sep, with any multi URL values joined by valSep,
// ignoring any values with keys in ignore.
//
// For example, to build a "ODBC" style connection string, can be used like the
// following:
//
//	genOptions(u.Query(), "", "=", ";", ",", false)
func genOptions(q url.Values, joiner, assign, sep, valSep string, skipWhenEmpty bool, ignore, ignorePrefixes []string) string {
	if len(q) == 0 {
		return ""
	}
	// make ignore map
	ig := make(map[string]bool, len(ignore))
	for _, v := range ignore {
		ig[strings.ToLower(v)] = true
	}
	// sort keys
	s := make([]string, len(q))
	var i int
	for k := range q {
		s[i] = k
		i++
	}
	sort.Strings(s)
	var opts []string
	for _, k := range s {
		if s := strings.ToLower(k); !ig[s] && !hasPrefix(s, ignorePrefixes) {
			val := strings.Join(q[k], valSep)
			if !skipWhenEmpty || val != "" {
				if val != "" {
					val = assign + val
				}
				opts = append(opts, k+val)
			}
		}
	}
	if len(opts) != 0 {
		return joiner + strings.Join(opts, sep)
	}
	return ""
}

// hasPrefix returns true when s begins with any listed prefix.
func hasPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
