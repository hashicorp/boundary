// The MIT License (MIT)
//
// Original Work
// Copyright (c) 2016 Matthias Kadenbach
// https://github.com/mattes/migrate
//
// Modified Work
// Copyright (c) 2018 Dale Hui
// https://github.com/golang-migrate/migrate
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package schema

import (
	"context"
	"database/sql"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/lib/pq"
)

var defaultMigrationsTable = "boundary_schema_version"

var (
	ErrNoDatabaseName = fmt.Errorf("no database name")
	ErrNoSchema       = fmt.Errorf("no schema")
	ErrDatabaseDirty  = fmt.Errorf("database is dirty")
)

type postgresConfig struct {
	DatabaseName string
	SchemaName   string
}

type postgres struct {
	// Locking and unlocking need to use the same connection
	conn     *sql.Conn
	db       *sql.DB
	isLocked bool

	advisoryLockId string
}

func newPostgres(ctx context.Context, instance *sql.DB) (*postgres, error) {
	if err := instance.PingContext(ctx); err != nil {
		return nil, err
	}

	query := `SELECT CURRENT_DATABASE(), CURRENT_SCHEMA()`
	var databaseName, schemaName string
	if err := instance.QueryRowContext(ctx, query).Scan(&databaseName, &schemaName); err != nil {
		return nil, err
	}

	if len(databaseName) == 0 {
		return nil, ErrNoDatabaseName
	}
	if len(schemaName) == 0 {
		return nil, ErrNoSchema
	}

	aid, err := generateAdvisoryLockId(databaseName, schemaName)
	if err != nil {
		return nil, err
	}

	conn, err := instance.Conn(ctx)

	if err != nil {
		return nil, err
	}

	px := &postgres{
		conn:           conn,
		db:             instance,
		advisoryLockId: aid,
	}

	if err := px.ensureVersionTable(ctx); err != nil {
		return nil, err
	}

	return px, nil
}

func (p *postgres) Open(ctx context.Context, u string) (*postgres, error) {
	db, err := sql.Open("postgres", u)
	if err != nil {
		return nil, err
	}

	px, err := newPostgres(ctx, db)

	if err != nil {
		return nil, err
	}

	return px, nil
}

func (p *postgres) Close() error {
	connErr := p.conn.Close()
	dbErr := p.db.Close()
	if connErr != nil || dbErr != nil {
		return fmt.Errorf("conn: %v, db: %v", connErr, dbErr)
	}
	return nil
}

// https://www.postgresql.org/docs/9.6/static/explicit-locking.html#ADVISORY-LOCKS
func (p *postgres) Lock(ctx context.Context) error {
	if p.isLocked {
		return fmt.Errorf("Already Locked")
	}

	// This will wait indefinitely until the lock can be acquired.
	query := `SELECT pg_advisory_lock($1)`
	if _, err := p.conn.ExecContext(ctx, query, p.advisoryLockId); err != nil {
		return err
	}

	p.isLocked = true
	return nil
}

func (p *postgres) Unlock(ctx context.Context) error {
	if !p.isLocked {
		return nil
	}

	query := `SELECT pg_advisory_unlock($1)`
	if _, err := p.conn.ExecContext(ctx, query, p.advisoryLockId); err != nil {
		return err
	}
	p.isLocked = false
	return nil
}

func (p *postgres) Run(ctx context.Context, migration io.Reader) error {
	migr, err := ioutil.ReadAll(migration)
	if err != nil {
		return err
	}
	// run migration
	query := string(migr[:])
	if _, err := p.conn.ExecContext(ctx, query); err != nil {
		if pgErr, ok := err.(*pq.Error); ok {
			var line uint
			var col uint
			var lineColOK bool
			if pgErr.Position != "" {
				if pos, err := strconv.ParseUint(pgErr.Position, 10, 64); err == nil {
					line, col, lineColOK = computeLineFromPos(query, int(pos))
				}
			}
			message := fmt.Sprintf("migration failed: %s", pgErr.Message)
			if lineColOK {
				message = fmt.Sprintf("%s (column %d)", message, col)
			}
			if pgErr.Detail != "" {
				message = fmt.Sprintf("%s, %s", message, pgErr.Detail)
			}
			// TODO: Add boundary domain errors and potentially record line number of migration.
			_ = line
			return err
		}
		return err
	}

	return nil
}

func computeLineFromPos(s string, pos int) (line uint, col uint, ok bool) {
	// replace crlf with lf
	s = strings.Replace(s, "\r\n", "\n", -1)
	// pg docs: pos uses index 1 for the first character, and positions are measured in characters not bytes
	runes := []rune(s)
	if pos > len(runes) {
		return 0, 0, false
	}
	sel := runes[:pos]
	line = uint(runesCount(sel, newLine) + 1)
	col = uint(pos - 1 - runesLastIndex(sel, newLine))
	return line, col, true
}

const newLine = '\n'

func runesCount(input []rune, target rune) int {
	var count int
	for _, r := range input {
		if r == target {
			count++
		}
	}
	return count
}

func runesLastIndex(input []rune, target rune) int {
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == target {
			return i
		}
	}
	return -1
}

func (p *postgres) SetVersion(ctx context.Context, version int, dirty bool) error {
	tx, err := p.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}

	query := `TRUNCATE ` + pq.QuoteIdentifier(defaultMigrationsTable)
	if _, err := tx.ExecContext(ctx, query); err != nil {
		if errRollback := tx.Rollback(); errRollback != nil {
			err = multierror.Append(err, errRollback)
		}
		return err
	}

	// Also re-write the schema version for nil dirty versions to prevent
	// empty schema version for failed down migration on the first migration
	// See: https://github.com/golang-migrate/migrate/issues/330
	if version >= 0 || (version == nilVersion && dirty) {
		query = `INSERT INTO ` + pq.QuoteIdentifier(defaultMigrationsTable) +
			` (version, dirty) VALUES ($1, $2)`
		if _, err := tx.ExecContext(ctx, query, version, dirty); err != nil {
			if errRollback := tx.Rollback(); errRollback != nil {
				err = multierror.Append(err, errRollback)
			}
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (p *postgres) Version(ctx context.Context) (version int, dirty bool, err error) {
	query := `SELECT version, dirty FROM ` + pq.QuoteIdentifier(defaultMigrationsTable) + ` LIMIT 1`
	err = p.conn.QueryRowContext(ctx, query).Scan(&version, &dirty)
	switch {
	case err == sql.ErrNoRows:
		return nilVersion, false, nil

	case err != nil:
		if e, ok := err.(*pq.Error); ok {
			if e.Code.Name() == "undefined_table" {
				return nilVersion, false, nil
			}
		}
		return 0, false, err

	default:
		return version, dirty, nil
	}
}

func (p *postgres) Drop(ctx context.Context) (err error) {
	// select all tables in current schema
	query := `SELECT table_name FROM information_schema.tables WHERE table_schema=(SELECT current_schema()) AND table_type='BASE TABLE'`
	tables, err := p.conn.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := tables.Close(); errClose != nil {
			err = multierror.Append(err, errClose)
		}
	}()

	// delete one table after another
	tableNames := make([]string, 0)
	for tables.Next() {
		var tableName string
		if err := tables.Scan(&tableName); err != nil {
			return err
		}
		if len(tableName) > 0 {
			tableNames = append(tableNames, tableName)
		}
	}
	if err := tables.Err(); err != nil {
		return err
	}

	if len(tableNames) > 0 {
		// delete one by one ...
		for _, t := range tableNames {
			query = `DROP TABLE IF EXISTS ` + pq.QuoteIdentifier(t) + ` CASCADE`
			if _, err := p.conn.ExecContext(ctx, query); err != nil {
				return err
			}
		}
	}

	return nil
}

// ensureVersionTable checks if versions table exists and, if not, creates it.
// Note that this function locks the database, which deviates from the usual
// convention of "caller locks" in the postgres type.
func (p *postgres) ensureVersionTable(ctx context.Context) (err error) {
	if err = p.Lock(ctx); err != nil {
		return err
	}

	defer func() {
		if e := p.Unlock(ctx); e != nil {
			if err == nil {
				err = e
			} else {
				err = multierror.Append(err, e)
			}
		}
	}()

	query := `CREATE TABLE IF NOT EXISTS ` + pq.QuoteIdentifier(defaultMigrationsTable) + ` (version bigint not null primary key, dirty boolean not null)`
	if _, err = p.conn.ExecContext(ctx, query); err != nil {
		return err
	}

	return nil
}

const advisoryLockIDSalt uint = 1486364155

// GenerateAdvisoryLockId inspired by rails migrations, see https://goo.gl/8o9bCT
func generateAdvisoryLockId(databaseName string, additionalNames ...string) (string, error) { // nolint: golint
	if len(additionalNames) > 0 {
		databaseName = strings.Join(append(additionalNames, databaseName), "\x00")
	}
	sum := crc32.ChecksumIEEE([]byte(databaseName))
	sum = sum * uint32(advisoryLockIDSalt)
	return fmt.Sprint(sum), nil
}
