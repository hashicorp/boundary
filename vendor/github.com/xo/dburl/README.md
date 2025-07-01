# About dburl

Package `dburl` provides a standard, URL style mechanism for parsing and
opening SQL database connection strings for [Go][go-project]. Provides
standardized way to [parse][goref-parse] and [open][goref-open] URLs for
popular databases PostgreSQL, MySQL, SQLite3, Oracle Database, Microsoft SQL
Server, in addition to most other SQL databases with a publicly available Go
driver.

[Overview][] | [Quickstart][] | [Examples][] | [Schemes][] | [Installing][] | [Using][] | [About][]

[Overview]: #database-connection-url-overview "Database Connection URL Overview"
[Quickstart]: #quickstart "Quickstart"
[Examples]: #example-urls "Example URLs"
[Schemes]: #database-schemes-aliases-and-drivers "Database Schemes, Aliases, and Drivers"
[Installing]: #installing "Installing"
[Using]: #using "Using"
[About]: #about "About"

[![Unit Tests][dburl-ci-status]][dburl-ci]
[![Go Reference][goref-dburl-status]][goref-dburl]
[![Discord Discussion][discord-status]][discord]

[dburl-ci]: https://github.com/xo/dburl/actions/workflows/test.yml
[dburl-ci-status]: https://github.com/xo/dburl/actions/workflows/test.yml/badge.svg
[goref-dburl]: https://pkg.go.dev/github.com/xo/dburl
[goref-dburl-status]: https://pkg.go.dev/badge/github.com/xo/dburl.svg
[discord]: https://discord.gg/yJKEzc7prt "Discord Discussion"
[discord-status]: https://img.shields.io/discord/829150509658013727.svg?label=Discord&logo=Discord&colorB=7289da&style=flat-square "Discord Discussion"

## Database Connection URL Overview

Supported database connection URLs are of the form:

```text
protocol+transport://user:pass@host/dbname?opt1=a&opt2=b
protocol:/path/to/file
```

Where:

| Component           | Description                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| protocol            | driver name or alias (see below)                                                     |
| transport           | "tcp", "udp", "unix" or driver name (odbc/oleodbc)                                   |
| user                | username                                                                             |
| pass                | password                                                                             |
| host                | host                                                                                 |
| dbname<sup>\*</sup> | database, instance, or service name/ID to connect to                                 |
| ?opt1=...           | additional database driver options (see respective SQL driver for available options) |

<i><sup><b>\*</b></sup> for Microsoft SQL Server, `/dbname` can be
`/instance/dbname`, where `/instance` is optional. For Oracle Database,
`/dbname` is of the form `/service/dbname` where `/service` is the service name
or SID, and `/dbname` is optional. Please see below for examples.</i>

## Quickstart

Database connection URLs in the above format can be parsed with the
[`dburl.Parse` func][goref-parse] as such:

```go
import (
    "github.com/xo/dburl"
)

u, err := dburl.Parse("postgresql://user:pass@localhost/mydatabase/?sslmode=disable")
if err != nil { /* ... */ }
```

Additionally, a simple helper, [`dburl.Open`][goref-open], is provided that
will parse, open, and return a [standard `sql.DB` database][goref-sql-db]
connection:

```go
import (
    "github.com/xo/dburl"
)

db, err := dburl.Open("sqlite:mydatabase.sqlite3?loc=auto")
if err != nil { /* ... */ }
```

## Example URLs

The following are example database connection URLs that can be handled by
[`dburl.Parse`][goref-parse] and [`dburl.Open`][goref-open]:

```text
postgres://user:pass@localhost/dbname
pg://user:pass@localhost/dbname?sslmode=disable
mysql://user:pass@localhost/dbname
mysql:/var/run/mysqld/mysqld.sock
sqlserver://user:pass@remote-host.com/dbname
mssql://user:pass@remote-host.com/instance/dbname
ms://user:pass@remote-host.com:port/instance/dbname?keepAlive=10
oracle://user:pass@somehost.com/sid
sap://user:pass@localhost/dbname
sqlite:/path/to/file.db
file:myfile.sqlite3?loc=auto
odbc+postgres://user:pass@localhost:port/dbname?option1=
```

## Database Schemes, Aliases, and Drivers

The following table lists the supported `dburl` protocol schemes (ie, driver),
additional aliases, and the related Go driver:

<!-- DRIVER DETAILS START -->
| Database             | Scheme / Tag    | Scheme Aliases                                  | Driver Package / Notes                                                      |
|----------------------|-----------------|-------------------------------------------------|-----------------------------------------------------------------------------|
| PostgreSQL           | `postgres`      | `pg`, `pgsql`, `postgresql`                     | [github.com/lib/pq][d-postgres]                                             |
| MySQL                | `mysql`         | `my`, `maria`, `aurora`, `mariadb`, `percona`   | [github.com/go-sql-driver/mysql][d-mysql]                                   |
| Microsoft SQL Server | `sqlserver`     | `ms`, `mssql`, `azuresql`                       | [github.com/microsoft/go-mssqldb][d-sqlserver]                              |
| Oracle Database      | `oracle`        | `or`, `ora`, `oci`, `oci8`, `odpi`, `odpi-c`    | [github.com/sijms/go-ora/v2][d-oracle]                                      |
| SQLite3              | `sqlite3`       | `sq`, `sqlite`, `file`                          | [github.com/mattn/go-sqlite3][d-sqlite3] <sup>[†][f-cgo]</sup>              |
| ClickHouse           | `clickhouse`    | `ch`                                            | [github.com/ClickHouse/clickhouse-go/v2][d-clickhouse]                      |
| CSVQ                 | `csvq`          | `cs`, `csv`, `tsv`, `json`                      | [github.com/mithrandie/csvq-driver][d-csvq]                                 |
|                      |                 |                                                 |                                                                             |
| Alibaba MaxCompute   | `maxcompute`    | `mc`                                            | [sqlflow.org/gomaxcompute][d-maxcompute]                                    |
| Alibaba Tablestore   | `ots`           | `ot`, `tablestore`                              | [github.com/aliyun/aliyun-tablestore-go-sql-driver][d-ots]                  |
| Apache Avatica       | `avatica`       | `av`, `phoenix`                                 | [github.com/apache/calcite-avatica-go/v5][d-avatica]                        |
| Apache H2            | `h2`            |                                                 | [github.com/jmrobles/h2go][d-h2]                                            |
| Apache Hive          | `hive`          | `hi`, `hive2`                                   | [sqlflow.org/gohive][d-hive]                                                |
| Apache Ignite        | `ignite`        | `ig`, `gridgain`                                | [github.com/amsokol/ignite-go-client/sql][d-ignite]                         |
| AWS Athena           | `athena`        | `s3`, `aws`, `awsathena`                        | [github.com/uber/athenadriver/go][d-athena]                                 |
| Azure CosmosDB       | `cosmos`        | `cm`                                            | [github.com/btnguyen2k/gocosmos][d-cosmos]                                  |
| Cassandra            | `cassandra`     | `ca`, `scy`, `scylla`, `datastax`, `cql`        | [github.com/MichaelS11/go-cql-driver][d-cassandra]                          |
| ChaiSQL              | `chai`          | `ci`, `genji`, `chaisql`                        | [github.com/chaisql/chai/driver][d-chai]                                    |
| Couchbase            | `couchbase`     | `n1`, `n1ql`                                    | [github.com/couchbase/go_n1ql][d-couchbase]                                 |
| Cznic QL             | `ql`            | `cznic`, `cznicql`                              | [modernc.org/ql][d-ql]                                                      |
| Databend             | `databend`      | `dd`, `bend`                                    | [github.com/datafuselabs/databend-go][d-databend]                           |
| Databricks           | `databricks`    | `br`, `brick`, `bricks`, `databrick`            | [github.com/databricks/databricks-sql-go][d-databricks]                     |
| DuckDB               | `duckdb`        | `dk`, `ddb`, `duck`, `file`                     | [github.com/marcboeker/go-duckdb][d-duckdb] <sup>[†][f-cgo]</sup>           |
| DynamoDb             | `dynamodb`      | `dy`, `dyn`, `dynamo`, `dynamodb`               | [github.com/btnguyen2k/godynamo][d-dynamodb]                                |
| Exasol               | `exasol`        | `ex`, `exa`                                     | [github.com/exasol/exasol-driver-go][d-exasol]                              |
| Firebird             | `firebird`      | `fb`, `firebirdsql`                             | [github.com/nakagami/firebirdsql][d-firebird]                               |
| FlightSQL            | `flightsql`     | `fl`, `flight`                                  | [github.com/apache/arrow/go/v12/arrow/flight/flightsql/driver][d-flightsql] |
| Google BigQuery      | `bigquery`      | `bq`                                            | [gorm.io/driver/bigquery/driver][d-bigquery]                                |
| Google Spanner       | `spanner`       | `sp`                                            | [github.com/googleapis/go-sql-spanner][d-spanner]                           |
| Microsoft ADODB      | `adodb`         | `ad`, `ado`                                     | [github.com/mattn/go-adodb][d-adodb]                                        |
| ModernC SQLite3      | `moderncsqlite` | `mq`, `modernsqlite`                            | [modernc.org/sqlite][d-moderncsqlite]                                       |
| MySQL MyMySQL        | `mymysql`       | `zm`, `mymy`                                    | [github.com/ziutek/mymysql/godrv][d-mymysql]                                |
| Netezza              | `netezza`       | `nz`, `nzgo`                                    | [github.com/IBM/nzgo/v12][d-netezza]                                        |
| PostgreSQL PGX       | `pgx`           | `px`                                            | [github.com/jackc/pgx/v5/stdlib][d-pgx]                                     |
| Presto               | `presto`        | `pr`, `prs`, `prestos`, `prestodb`, `prestodbs` | [github.com/prestodb/presto-go-client/presto][d-presto]                     |
| RamSQL               | `ramsql`        | `rm`, `ram`                                     | [github.com/proullon/ramsql/driver][d-ramsql]                               |
| SAP ASE              | `sapase`        | `ax`, `ase`, `tds`                              | [github.com/thda/tds][d-sapase]                                             |
| SAP HANA             | `saphana`       | `sa`, `sap`, `hana`, `hdb`                      | [github.com/SAP/go-hdb/driver][d-saphana]                                   |
| Snowflake            | `snowflake`     | `sf`                                            | [github.com/snowflakedb/gosnowflake][d-snowflake]                           |
| Trino                | `trino`         | `tr`, `trs`, `trinos`                           | [github.com/trinodb/trino-go-client/trino][d-trino]                         |
| Vertica              | `vertica`       | `ve`                                            | [github.com/vertica/vertica-sql-go][d-vertica]                              |
| VoltDB               | `voltdb`        | `vo`, `vdb`, `volt`                             | [github.com/VoltDB/voltdb-client-go/voltdbclient][d-voltdb]                 |
| YDB                  | `ydb`           | `yd`, `yds`, `ydbs`                             | [github.com/ydb-platform/ydb-go-sdk/v3][d-ydb]                              |
|                      |                 |                                                 |                                                                             |
| GO DRiver for ORacle | `godror`        | `gr`                                            | [github.com/godror/godror][d-godror] <sup>[†][f-cgo]</sup>                  |
| ODBC                 | `odbc`          | `od`                                            | [github.com/alexbrainman/odbc][d-odbc] <sup>[†][f-cgo]</sup>                |
|                      |                 |                                                 |                                                                             |
| Amazon Redshift      | `postgres`      | `rs`, `redshift`                                | [github.com/lib/pq][d-postgres] <sup>[‡][f-wire]</sup>                      |
| CockroachDB          | `postgres`      | `cr`, `cdb`, `crdb`, `cockroach`, `cockroachdb` | [github.com/lib/pq][d-postgres] <sup>[‡][f-wire]</sup>                      |
| OLE ODBC             | `adodb`         | `oo`, `ole`, `oleodbc`                          | [github.com/mattn/go-adodb][d-adodb] <sup>[‡][f-wire]</sup>                 |
| SingleStore MemSQL   | `mysql`         | `me`, `memsql`                                  | [github.com/go-sql-driver/mysql][d-mysql] <sup>[‡][f-wire]</sup>            |
| TiDB                 | `mysql`         | `ti`, `tidb`                                    | [github.com/go-sql-driver/mysql][d-mysql] <sup>[‡][f-wire]</sup>            |
| Vitess Database      | `mysql`         | `vt`, `vitess`                                  | [github.com/go-sql-driver/mysql][d-mysql] <sup>[‡][f-wire]</sup>            |
|                      |                 |                                                 |                                                                             |
| Apache Impala        | `impala`        | `im`                                            | [github.com/bippio/go-impala][d-impala]                                     |

[d-adodb]: https://github.com/mattn/go-adodb
[d-athena]: https://github.com/uber/athenadriver
[d-avatica]: https://github.com/apache/calcite-avatica-go
[d-bigquery]: https://github.com/go-gorm/bigquery
[d-cassandra]: https://github.com/MichaelS11/go-cql-driver
[d-chai]: https://github.com/chaisql/chai
[d-clickhouse]: https://github.com/ClickHouse/clickhouse-go
[d-cosmos]: https://github.com/btnguyen2k/gocosmos
[d-couchbase]: https://github.com/couchbase/go_n1ql
[d-csvq]: https://github.com/mithrandie/csvq-driver
[d-databend]: https://github.com/datafuselabs/databend-go
[d-databricks]: https://github.com/databricks/databricks-sql-go
[d-duckdb]: https://github.com/marcboeker/go-duckdb
[d-dynamodb]: https://github.com/btnguyen2k/godynamo
[d-exasol]: https://github.com/exasol/exasol-driver-go
[d-firebird]: https://github.com/nakagami/firebirdsql
[d-flightsql]: https://github.com/apache/arrow/tree/main/go/arrow/flight/flightsql/driver
[d-godror]: https://github.com/godror/godror
[d-h2]: https://github.com/jmrobles/h2go
[d-hive]: https://github.com/sql-machine-learning/gohive
[d-ignite]: https://github.com/amsokol/ignite-go-client
[d-impala]: https://github.com/bippio/go-impala
[d-maxcompute]: https://github.com/sql-machine-learning/gomaxcompute
[d-moderncsqlite]: https://gitlab.com/cznic/sqlite
[d-mymysql]: https://github.com/ziutek/mymysql
[d-mysql]: https://github.com/go-sql-driver/mysql
[d-netezza]: https://github.com/IBM/nzgo
[d-odbc]: https://github.com/alexbrainman/odbc
[d-oracle]: https://github.com/sijms/go-ora
[d-ots]: https://github.com/aliyun/aliyun-tablestore-go-sql-driver
[d-pgx]: https://github.com/jackc/pgx
[d-postgres]: https://github.com/lib/pq
[d-presto]: https://github.com/prestodb/presto-go-client
[d-ql]: https://gitlab.com/cznic/ql
[d-ramsql]: https://github.com/proullon/ramsql
[d-sapase]: https://github.com/thda/tds
[d-saphana]: https://github.com/SAP/go-hdb
[d-snowflake]: https://github.com/snowflakedb/gosnowflake
[d-spanner]: https://github.com/googleapis/go-sql-spanner
[d-sqlite3]: https://github.com/mattn/go-sqlite3
[d-sqlserver]: https://github.com/microsoft/go-mssqldb
[d-trino]: https://github.com/trinodb/trino-go-client
[d-vertica]: https://github.com/vertica/vertica-sql-go
[d-voltdb]: https://github.com/VoltDB/voltdb-client-go
[d-ydb]: https://github.com/ydb-platform/ydb-go-sdk
<!-- DRIVER DETAILS END -->

[f-cgo]: #f-cgo "Requires CGO"
[f-wire]: #f-wire "Wire compatible"

<p>
  <i>
    <a id="f-cgo"><sup>†</sup> Requires CGO</a><br>
    <a id="f-wire"><sup>‡</sup> Wire compatible (see respective driver)</a>
  </i>
</p>

Any protocol scheme `alias://` can be used in place of `protocol://`, and will
work identically with [`dburl.Parse`][goref-parse] and [`dburl.Open`][goref-open].

## Installing

Install in the usual Go fashion:

```sh
$ go get github.com/xo/dburl@latest
```

## Using

`dburl` does not import any of Go's SQL drivers, as it only provides a way to
[parse][goref-parse] and [open][goref-open] database URL stylized connection
strings. As such, it is necessary to explicitly `import` the relevant SQL driver:

```go
import (
    // import Microsoft SQL Server driver
    _ "github.com/microsoft/go-mssqldb"
)
```

See the [database schemes table][Schemes] above for a list of the
expected Go driver `import`'s.

Additional examples and API details can be found in [the `dburl` package
documentation][goref-dburl].

### URL Parsing Rules

[`dburl.Parse`][goref-parse] and [`dburl.Open`][goref-open] rely primarily on
Go's standard [`net/url.URL`][goref-net-url] type, and as such, parsing or
opening database connection URLs with `dburl` are subject to the same rules,
conventions, and semantics as [Go's `net/url.Parse` func][goref-net-url-parse].

## Example

A [full example](_example/example.go) for reference:

```go
// _example/example.go
package main

import (
	"fmt"
	"log"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/xo/dburl"
)

func main() {
	db, err := dburl.Open("sqlserver://user:pass@localhost/dbname")
	if err != nil {
		log.Fatal(err)
	}
	var name string
	if err := db.QueryRow(`SELECT name FROM mytable WHERE id=10`).Scan(&name); err != nil {
		log.Fatal(err)
	}
	fmt.Println("name:", name)
}
```

## Scheme Resolution

By default on non-Windows systems, `dburl` will resolve paths on disk, and URLs
with `file:` schemes to an appropriate database driver:

1. Directories will resolve as `postgres:` URLs
2. Unix sockets will resolve as `mysql:` URLs
3. Regular files will have their headers checked to determine if they are
   either `sqlite3:` or `duckdb:` files
4. Non-existent files will test their file extension against well-known
   `sqlite3:` and `duckdb:` file extensions and open with the appropriate
   scheme

If this behavior is undesired, it can be disabled by providing different
implementations for [`dburl.Stat`][goref-variables] and [`dburl.OpenFile`][goref-variables],
or alternately by setting [`dburl.ResolveSchemeType`][goref-variables] to false:

```go
import "github.com/xo/dburl"

func init() {
    dburl.ResolveSchemeType = false
}
```

## About

`dburl` was built primarily to support these projects:

- [usql][usql] - a universal command-line interface for SQL databases
- [xo][xo] - a command-line tool to generate code for SQL databases

[go-project]: https://go.dev/project
[goref-open]: https://pkg.go.dev/github.com/xo/dburl#Open
[goref-variables]: https://pkg.go.dev/github.com/xo/dburl#pkg-variables
[goref-parse]: https://pkg.go.dev/github.com/xo/dburl#Parse
[goref-sql-db]: https://pkg.go.dev/database/sql#DB
[goref-net-url]: https://pkg.go.dev/net/url#URL
[goref-net-url-parse]: https://pkg.go.dev/net/url#URL.Parse
[usql]: https://github.com/xo/usql
[xo]: https://github.com/xo/xo
