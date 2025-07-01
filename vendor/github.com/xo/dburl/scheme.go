package dburl

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
)

// Transport is the allowed transport protocol types in a database [URL] scheme.
type Transport uint

// Transport types.
const (
	TransportNone Transport = 0
	TransportTCP  Transport = 1
	TransportUDP  Transport = 2
	TransportUnix Transport = 4
	TransportAny  Transport = 8
)

// Scheme wraps information used for registering a database URL scheme for use
// with [Parse]/[Open].
type Scheme struct {
	// Driver is the name of the SQL driver that is set as the Scheme in
	// Parse'd URLs and is the driver name expected by the standard sql.Open
	// calls.
	//
	// Note: a 2 letter alias will always be registered for the Driver as the
	// first 2 characters of the Driver, unless one of the Aliases includes an
	// alias that is 2 characters.
	Driver string
	// Generator is the func responsible for generating a DSN based on parsed
	// URL information.
	//
	// Note: this func should not modify the passed URL.
	Generator func(*URL) (string, string, error)
	// Transport are allowed protocol transport types for the scheme.
	Transport Transport
	// Opaque toggles Parse to not re-process URLs with an "opaque" component.
	Opaque bool
	// Aliases are any additional aliases for the scheme.
	Aliases []string
	// Override is the Go SQL driver to use instead of Driver.
	//
	// Used for "wire compatible" driver schemes.
	Override string
}

// BaseSchemes returns the supported base schemes.
func BaseSchemes() []Scheme {
	return []Scheme{
		{
			"file",
			GenOpaque, 0, true,
			[]string{"file"},
			"",
		},
		// core databases
		{
			"mysql",
			GenMysql, TransportTCP | TransportUDP | TransportUnix,
			false,
			[]string{"mariadb", "maria", "percona", "aurora"},
			"",
		},
		{
			"oracle",
			GenFromURL("oracle://localhost:1521"), 0, false,
			[]string{"ora", "oci", "oci8", "odpi", "odpi-c"},
			"",
		},
		{
			"postgres",
			GenPostgres, TransportUnix, false,
			[]string{"pg", "postgresql", "pgsql"},
			"",
		},
		{
			"sqlite3",
			GenOpaque, 0, true,
			[]string{"sqlite"},
			"",
		},
		{
			"sqlserver",
			GenSqlserver, 0, false,
			[]string{"ms", "mssql", "azuresql"},
			"",
		},
		// wire compatibles
		{
			"cockroachdb",
			GenFromURL("postgres://localhost:26257/?sslmode=disable"), 0, false,
			[]string{"cr", "cockroach", "crdb", "cdb"},
			"postgres",
		},
		{
			"memsql", GenMysql, 0, false, nil, "mysql",
		},
		{
			"redshift",
			GenFromURL("postgres://localhost:5439/"), 0, false,
			[]string{"rs"},
			"postgres",
		},
		{
			"tidb",
			GenMysql, 0, false, nil, "mysql",
		},
		{
			"vitess",
			GenMysql, 0, false,
			[]string{"vt"},
			"mysql",
		},
		// alternate implementations
		{
			"godror",
			GenGodror, 0, false,
			[]string{"gr"},
			"",
		},
		{
			"moderncsqlite",
			GenOpaque, 0, true,
			[]string{"mq", "modernsqlite"},
			"",
		},
		{
			"mymysql",
			GenMymysql, TransportTCP | TransportUDP | TransportUnix, false,
			[]string{"zm", "mymy"},
			"",
		},
		{
			"pgx",
			GenFromURL("postgres://localhost:5432/"), TransportUnix, false,
			[]string{"px"},
			"",
		},
		// other databases
		{
			"adodb",
			GenAdodb, 0, false,
			[]string{"ado"},
			"",
		},
		{
			"awsathena",
			GenScheme("s3"), 0, false,
			[]string{"s3", "aws", "athena"},
			"",
		},
		{
			"avatica",
			GenFromURL("http://localhost:8765/"), 0, false,
			[]string{"phoenix"},
			"",
		},
		{
			"bigquery",
			GenScheme("bigquery"), 0, false,
			[]string{"bq"},
			"",
		},
		{
			"clickhouse",
			GenClickhouse, TransportAny, false,
			[]string{"ch"},
			"",
		},
		{
			"cosmos",
			GenCosmos, 0, false,
			[]string{"cm"},
			"",
		},
		{
			"cql",
			GenCassandra, 0, false,
			[]string{"ca", "cassandra", "datastax", "scy", "scylla"},
			"",
		},
		{
			"csvq",
			GenOpaque, 0, true,
			[]string{"csv", "tsv", "json"},
			"",
		},
		{
			"databend",
			GenDatabend, 0, false,
			[]string{"dd", "bend"},
			"",
		},
		{
			"databricks",
			GenDatabricks, 0, false,
			[]string{"br", "brick", "bricks", "databrick"},
			"",
		},
		{
			"duckdb",
			GenOpaque, 0, true,
			[]string{"dk", "ddb", "duck"},
			"",
		},
		{
			"godynamo",
			GenDynamo, 0, false,
			[]string{"dy", "dyn", "dynamo", "dynamodb"},
			"",
		},
		{
			"exasol",
			GenExasol, 0, false,
			[]string{"ex", "exa"},
			"",
		},
		{
			"firebirdsql",
			GenFirebird, 0, false,
			[]string{"fb", "firebird"},
			"",
		},
		{
			"flightsql",
			GenScheme("flightsql"), 0, false,
			[]string{"fl", "flight"},
			"",
		},
		{
			"chai",
			GenOpaque, 0, true,
			[]string{"ci", "chaisql", "genji"},
			"",
		},
		{
			"h2",
			GenFromURL("h2://localhost:9092/"), 0, false, nil, "",
		},
		{
			"hdb",
			GenScheme("hdb"), 0, false,
			[]string{"sa", "saphana", "sap", "hana"},
			"",
		},
		{
			"hive",
			GenFromURL("truncate://localhost:10000/"), 0, false,
			[]string{"hive2"},
			"",
		},
		{
			"ignite",
			GenIgnite, 0, false,
			[]string{"ig", "gridgain"},
			"",
		},
		{
			"impala",
			GenScheme("impala"), 0, false, nil, "",
		},
		{
			"maxcompute",
			GenFromURL("truncate://localhost/"), 0, false,
			[]string{"mc"},
			"",
		},
		{
			"n1ql",
			GenFromURL("http://localhost:8093/"), 0, false,
			[]string{"couchbase"},
			"",
		},
		{
			"nzgo",
			GenPostgres, TransportUnix, false,
			[]string{"nz", "netezza"},
			"",
		},
		{
			"odbc",
			GenOdbc, TransportAny, false, nil, "",
		},
		{
			"oleodbc",
			GenOleodbc, TransportAny, false,
			[]string{"oo", "ole"},
			"adodb",
		},
		{
			"ots",
			GenTableStore, TransportAny, false,
			[]string{"tablestore"},
			"",
		},
		{
			"presto",
			GenPresto, 0, false,
			[]string{"prestodb", "prestos", "prs", "prestodbs"},
			"",
		},
		{
			"ql",
			GenOpaque, 0, true,
			[]string{"ql", "cznic", "cznicql"},
			"",
		},
		{
			"ramsql",
			GenFromURL("truncate://ramsql"), 0, false,
			[]string{"rm", "ram"},
			"",
		},
		{
			"snowflake",
			GenSnowflake, 0, false,
			[]string{"sf"},
			"",
		},
		{
			"spanner",
			GenSpanner, 0, false,
			[]string{"sp"},
			"",
		},
		{
			"tds",
			GenFromURL("http://localhost:5000/"), 0, false,
			[]string{"ax", "ase", "sapase"},
			"",
		},
		{
			"trino",
			GenPresto, 0, false,
			[]string{"trino", "trinos", "trs"},
			"",
		},
		{
			"vertica",
			GenFromURL("vertica://localhost:5433/"), 0, false, nil, "",
		},
		{
			"voltdb",
			GenVoltdb, 0, false,
			[]string{"volt", "vdb"},
			"",
		},
		{
			"ydb",
			GenYDB, 0, false,
			[]string{"yd", "yds", "ydbs"},
			"",
		},
	}
}

func init() {
	// register schemes
	schemes := BaseSchemes()
	schemeMap = make(map[string]*Scheme, len(schemes))
	for _, scheme := range schemes {
		Register(scheme)
	}
	RegisterFileType("duckdb", isDuckdbHeader, `(?i)\.duckdb$`)
	RegisterFileType("sqlite3", isSqlite3Header, `(?i)\.(db|sqlite|sqlite3)$`)
}

// schemeMap is the map of registered schemes.
var schemeMap map[string]*Scheme

// registerAlias registers a alias for an already registered Scheme.
func registerAlias(name, alias string, doSort bool) {
	scheme, ok := schemeMap[name]
	if !ok {
		panic(fmt.Sprintf("scheme %s not registered", name))
	}
	if doSort && contains(scheme.Aliases, alias) {
		panic(fmt.Sprintf("scheme %s already has alias %s", name, alias))
	}
	if _, ok := schemeMap[alias]; ok {
		panic(fmt.Sprintf("scheme %s already registered", alias))
	}
	scheme.Aliases = append(scheme.Aliases, alias)
	if doSort {
		sort.Slice(scheme.Aliases, func(i, j int) bool {
			if len(scheme.Aliases[i]) <= len(scheme.Aliases[j]) {
				return true
			}
			if len(scheme.Aliases[j]) < len(scheme.Aliases[i]) {
				return false
			}
			return scheme.Aliases[i] < scheme.Aliases[j]
		})
	}
	schemeMap[alias] = scheme
}

// Register registers a [Scheme].
func Register(scheme Scheme) {
	if scheme.Generator == nil {
		panic("must specify Generator when registering Scheme")
	}
	if scheme.Opaque && scheme.Transport&TransportUnix != 0 {
		panic("scheme must support only Opaque or Unix protocols, not both")
	}
	// check if registered
	if _, ok := schemeMap[scheme.Driver]; ok {
		panic(fmt.Sprintf("scheme %s already registered", scheme.Driver))
	}
	sz := &Scheme{
		Driver:    scheme.Driver,
		Generator: scheme.Generator,
		Transport: scheme.Transport,
		Opaque:    scheme.Opaque,
		Override:  scheme.Override,
	}
	schemeMap[scheme.Driver] = sz
	// add aliases
	var hasShort bool
	for _, alias := range scheme.Aliases {
		if len(alias) == 2 {
			hasShort = true
		}
		if scheme.Driver != alias {
			registerAlias(scheme.Driver, alias, false)
		}
	}
	if !hasShort && len(scheme.Driver) > 2 {
		registerAlias(scheme.Driver, scheme.Driver[:2], false)
	}
	// ensure always at least one alias, and that if Driver is 2 characters,
	// that it gets added as well
	if len(sz.Aliases) == 0 || len(scheme.Driver) == 2 {
		sz.Aliases = append(sz.Aliases, scheme.Driver)
	}
	// sort
	sort.Slice(sz.Aliases, func(i, j int) bool {
		if len(sz.Aliases[i]) <= len(sz.Aliases[j]) {
			return true
		}
		if len(sz.Aliases[j]) < len(sz.Aliases[i]) {
			return false
		}
		return sz.Aliases[i] < sz.Aliases[j]
	})
}

// Unregister unregisters a scheme and all associated aliases, returning the
// removed [Scheme].
func Unregister(name string) *Scheme {
	if scheme, ok := schemeMap[name]; ok {
		for _, alias := range scheme.Aliases {
			delete(schemeMap, alias)
		}
		delete(schemeMap, name)
		return scheme
	}
	return nil
}

// RegisterAlias registers an additional alias for a registered scheme.
func RegisterAlias(name, alias string) {
	registerAlias(name, alias, true)
}

// fileTypes are registered header recognition funcs.
var fileTypes []fileType

// RegisterFileType registers a file header recognition func, and extension regexp.
func RegisterFileType(driver string, f func([]byte) bool, ext string) {
	extRE, err := regexp.Compile(ext)
	if err != nil {
		panic(fmt.Sprintf("invalid extension regexp %q: %v", ext, err))
	}
	fileTypes = append(fileTypes, fileType{
		driver: driver,
		f:      f,
		ext:    extRE,
	})
}

// fileType wraps file type information.
type fileType struct {
	driver string
	f      func([]byte) bool
	ext    *regexp.Regexp
}

// FileTypes returns the registered file types.
func FileTypes() []string {
	var v []string
	for _, typ := range fileTypes {
		v = append(v, typ.driver)
	}
	return v
}

// Protocols returns list of all valid protocol aliases for a registered
// [Scheme] name.
func Protocols(name string) []string {
	if scheme, ok := schemeMap[name]; ok {
		return append([]string{scheme.Driver}, scheme.Aliases...)
	}
	return nil
}

// SchemeDriverAndAliases returns the registered driver and aliases for a
// database scheme.
func SchemeDriverAndAliases(name string) (string, []string) {
	if scheme, ok := schemeMap[name]; ok {
		driver := scheme.Driver
		if scheme.Override != "" {
			driver = scheme.Override
		}
		var aliases []string
		for _, alias := range scheme.Aliases {
			if alias == driver {
				continue
			}
			aliases = append(aliases, alias)
		}
		sort.Slice(aliases, func(i, j int) bool {
			if len(aliases[i]) <= len(aliases[j]) {
				return true
			}
			if len(aliases[j]) < len(aliases[i]) {
				return false
			}
			return aliases[i] < aliases[j]
		})
		return driver, aliases
	}
	return "", nil
}

// ShortAlias returns the short alias for the scheme name.
func ShortAlias(name string) string {
	if scheme, ok := schemeMap[name]; ok {
		return scheme.Aliases[0]
	}
	return ""
}

// isSqlite3Header returns true when the passed header is empty or starts with
// the SQLite3 header.
//
// See: https://www.sqlite.org/fileformat.html
func isSqlite3Header(buf []byte) bool {
	return bytes.HasPrefix(buf, sqlite3Header)
}

// sqlite3Header is the sqlite3 header.
var sqlite3Header = []byte("SQLite format 3\000")

// isDuckdbHeader returns true when the passed header is a DuckDB header.
//
// See: https://duckdb.org/internals/storage
func isDuckdbHeader(buf []byte) bool {
	return duckdbRE.Match(buf)
}

// duckdbRE is the duckdb storage header regexp.
var duckdbRE = regexp.MustCompile(`^.{8}DUCK.{8}`)

// contains determines if v contains s.
func contains(v []string, s string) bool {
	for _, z := range v {
		if z == s {
			return true
		}
	}
	return false
}
