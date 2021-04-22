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

package postgres

// error codes https://github.com/lib/pq/blob/master/error.go

import (
	"bytes"
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/dhui/dktest"
	"github.com/golang-migrate/migrate/v4/dktesting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pgPassword = "postgres"
)

var (
	opts = dktest.Options{
		Env:          map[string]string{"POSTGRES_PASSWORD": pgPassword},
		PortRequired: true, ReadyFunc: isReady,
	}
	// Supported versions: https://www.postgresql.org/support/versioning/
	specs = []dktesting.ContainerSpec{
		{ImageName: "postgres:12", Options: opts},
	}
)

func pgConnectionString(host, port string) string {
	return fmt.Sprintf("postgres://postgres:%s@%s:%s/postgres?sslmode=disable", pgPassword, host, port)
}

func isReady(ctx context.Context, c dktest.ContainerInfo) bool {
	ip, port, err := c.FirstPort()
	if err != nil {
		return false
	}

	db, err := sql.Open("postgres", pgConnectionString(ip, port))
	if err != nil {
		return false
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Println("close error:", err)
		}
	}()
	if err = db.PingContext(ctx); err != nil {
		switch err {
		case sqldriver.ErrBadConn, io.EOF:
			return false
		default:
			log.Println(err)
		}
		return false
	}

	return true
}

func TestDbStuff(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		d, err := open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Error(err)
			}
		}()
		test(t, d, []byte("SELECT 1"))
	})
}

func TestCurrentState_NoVersionTable(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		d, err := open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Error(err)
			}
		}()
		// Drop the version table so calls to CurrentState don't rely on that
		require.NoError(t, d.drop(ctx))

		v, alreadyRan, dirt, err := d.CurrentState(ctx)
		assert.NoError(t, err)
		assert.False(t, alreadyRan)
		assert.Equal(t, v, nilVersion)
		assert.False(t, dirt)
	})
}

func TestCurrentState_ToManyTables(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		d, err := open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Error(err)
			}
		}()

		// Create the most recent table
		require.NoError(t, d.EnsureVersionTable(ctx))

		// Create the legacy version of the table.
		oldTableCreate := `create table if not exists schema_migrations (version bigint primary key, dirty boolean not null)`
		_, err = d.conn.ExecContext(ctx, oldTableCreate)
		require.NoError(t, err)
		v, alreadyRan, dirt, err := d.CurrentState(ctx)
		assert.Error(t, err)
		assert.True(t, alreadyRan)
		assert.Equal(t, v, nilVersion)
		assert.False(t, dirt)
	})
}

func TestMultiStatement(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		d, err := open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Error(err)
			}
		}()
		if err := d.EnsureVersionTable(ctx); err != nil {
			t.Fatalf("expected err to be nil, got %v", err)
		}

		if err := d.Run(ctx, strings.NewReader("CREATE TABLE foo (foo text); CREATE TABLE bar (bar text);"), 2); err != nil {
			t.Fatalf("expected err to be nil, got %v", err)
		}

		// make sure second table exists
		var exists bool
		if err := d.conn.QueryRowContext(context.Background(), "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'bar' AND table_schema = (SELECT current_schema()))").Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("expected table bar to exist")
		}
	})
}

func TestTransaction(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		d, err := open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Error(err)
			}
		}()

		v, alreadyRan, dirty, err := d.CurrentState(ctx)
		assert.NoError(t, err)
		assert.False(t, alreadyRan)
		assert.False(t, dirty)
		assert.Equal(t, -1, v)

		// Fail the initial setup of the db.
		assert.NoError(t, d.StartRun(ctx))
		assert.NoError(t, d.EnsureVersionTable(ctx))
		assert.Error(t, d.Run(ctx, strings.NewReader("SELECT 1 from nonExistantTable"), 3))
		assert.Error(t, d.CommitRun())

		v, alreadyRan, dirty, err = d.CurrentState(ctx)
		assert.NoError(t, err)
		assert.False(t, alreadyRan)
		assert.False(t, dirty)
		assert.Equal(t, -1, v)

		assert.NoError(t, d.StartRun(ctx))
		assert.NoError(t, d.EnsureVersionTable(ctx))
		assert.NoError(t, d.Run(ctx, strings.NewReader("CREATE TABLE foo (foo text);"), 2))
		assert.NoError(t, d.Run(ctx, strings.NewReader("SELECT 1;"), 3))
		assert.NoError(t, d.CommitRun())

		v, alreadyRan, dirty, err = d.CurrentState(ctx)
		assert.NoError(t, err)
		assert.True(t, alreadyRan)
		assert.False(t, dirty)
		assert.Equal(t, 3, v)

		assert.NoError(t, d.StartRun(ctx))
		assert.NoError(t, d.Run(ctx, strings.NewReader("CREATE TABLE bar (bar text);"), 20))
		assert.Error(t, d.Run(ctx, strings.NewReader("SELECT 1 FROM NonExistingTable"), 30))
		assert.Error(t, d.CommitRun())

		v, alreadyRan, dirty, err = d.CurrentState(ctx)
		assert.NoError(t, err)
		assert.True(t, alreadyRan)
		assert.False(t, dirty)
		assert.Equal(t, 3, v)
	})
}

func TestWithSchema(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		require.NoError(t, err)

		addr := pgConnectionString(ip, port)
		d, err := open(t, ctx, addr)
		require.NoError(t, err)
		defer func() {
			if err := d.close(t); err != nil {
				t.Fatal(err)
			}
		}()
		require.NoError(t, d.EnsureVersionTable(ctx))

		// create foobar schema
		require.NoError(t, d.Run(ctx, strings.NewReader("CREATE SCHEMA foobar AUTHORIZATION postgres"), 1))

		// re-connect using that schema
		d2, err := open(t, ctx, fmt.Sprintf("postgres://postgres:%s@%v:%v/postgres?sslmode=disable&search_path=foobar",
			pgPassword, ip, port))
		require.NoError(t, err)
		defer func() {
			if err := d2.close(t); err != nil {
				t.Fatal(err)
			}
		}()

		version, alreadyRan, _, err := d2.CurrentState(ctx)
		require.NoError(t, err)
		require.Equal(t, nilVersion, version)
		assert.False(t, alreadyRan)

		// now update CurrentState and compare
		require.NoError(t, d2.EnsureVersionTable(ctx))
		require.NoError(t, d2.setVersion(ctx, 2, false))
		version, alreadyRan, _, err = d2.CurrentState(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, version)
		assert.True(t, alreadyRan)

		// meanwhile, the public schema still has the other CurrentState
		version, alreadyRan, _, err = d.CurrentState(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, version)
		assert.True(t, alreadyRan)
	})
}

func TestPostgres_Lock(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		ps, err := open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}

		test(t, ps, []byte("SELECT 1"))

		err = ps.Lock(ctx)
		if err != nil {
			t.Fatal(err)
		}

		err = ps.Unlock(ctx)
		if err != nil {
			t.Fatal(err)
		}

		err = ps.Lock(ctx)
		if err != nil {
			t.Fatal(err)
		}

		err = ps.Unlock(ctx)
		if err != nil {
			t.Fatal(err)
		}

		// make sure we call call Unlock in an idempotent manner.
		err = ps.Unlock(ctx)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestEnsureTable_Fresh(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p, err := open(t, ctx, addr)
		if err != nil {
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			require.NoError(t, p.close(t))
		})

		tableCreated := false
		query := "SELECT exists (SELECT 1 FROM information_schema.tables WHERE table_schema=(SELECT current_schema()) AND table_name = '" + defaultMigrationsTable + "')"
		assert.NoError(t, p.db.QueryRowContext(ctx, query).Scan(&tableCreated))
		assert.False(t, tableCreated)

		assert.NoError(t, p.EnsureVersionTable(ctx))
		assert.NoError(t, p.db.QueryRowContext(ctx, query).Scan(&tableCreated))
		assert.True(t, tableCreated)
	})
}

func TestEnsureTable_ExistingTable(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p, err := open(t, ctx, addr)
		if err != nil {
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			require.NoError(t, p.close(t))
		})
		assert.NoError(t, p.EnsureVersionTable(ctx))

		oldTableCreate := `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint primary key, dirty boolean not null)`
		_, err = p.db.ExecContext(ctx, oldTableCreate)
		assert.NoError(t, err)

		assert.NoError(t, p.EnsureVersionTable(ctx))
	})
}

func TestEnsureTable_OldTable(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p, err := open(t, ctx, addr)
		if err != nil {
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			require.NoError(t, p.close(t))
		})

		oldTableCreate := `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint primary key, dirty boolean not null)`
		_, err = p.db.ExecContext(ctx, oldTableCreate)
		assert.NoError(t, err)

		tableExists := false
		oldTableCheck := "SELECT exists (SELECT 1 FROM information_schema.tables WHERE table_schema=(SELECT current_schema()) AND table_name = 'schema_migrations')"
		assert.NoError(t, p.db.QueryRowContext(ctx, oldTableCheck).Scan(&tableExists))
		assert.True(t, tableExists)

		query := "SELECT exists (SELECT 1 FROM information_schema.tables WHERE table_schema=(SELECT current_schema()) AND table_name = '" + defaultMigrationsTable + "')"
		assert.NoError(t, p.db.QueryRowContext(ctx, query).Scan(&tableExists))
		assert.False(t, tableExists)

		assert.NoError(t, p.EnsureVersionTable(ctx))

		assert.NoError(t, p.db.QueryRowContext(ctx, oldTableCheck).Scan(&tableExists))
		assert.False(t, tableExists)
		assert.NoError(t, p.db.QueryRowContext(ctx, query).Scan(&tableExists))
		assert.True(t, tableExists)
	})
}

func TestRollback(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p, err := open(t, ctx, addr)
		if err != nil {
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			require.NoError(t, p.close(t))
		})

		assert.NoError(t, p.StartRun(ctx))
		assert.NoError(t, p.EnsureVersionTable(ctx))
		assert.NoError(t, p.Run(ctx, bytes.NewReader([]byte("create table if not exists foo (foo text)")), 2))
		var exists bool
		query := "select exists (select 1 from information_schema.tables where table_name = 'foo' and table_schema = (select current_schema()))"
		assert.NoError(t, p.conn.QueryRowContext(context.Background(), query).Scan(&exists))
		assert.True(t, exists)
		assert.NoError(t, p.Rollback())

		assert.NoError(t, p.conn.QueryRowContext(context.Background(), query).Scan(&exists))
		assert.False(t, exists)
	})
}

func TestRun_Error(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.Background()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p, err := open(t, ctx, addr)
		if err != nil {
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			require.NoError(t, p.close(t))
		})

		err = p.Run(ctx, bytes.NewReader([]byte("SELECT *\nFROM foo")), 2)
		assert.Error(t, err)
	})
}

func Test_computeLineFromPos(t *testing.T) {
	testcases := []struct {
		pos      int
		wantLine uint
		wantCol  uint
		input    string
		wantOk   bool
	}{
		{
			15, 2, 6, "SELECT *\nFROM foo", true, // foo table does not exists
		},
		{
			16, 3, 6, "SELECT *\n\nFROM foo", true, // foo table does not exists, empty line
		},
		{
			25, 3, 7, "SELECT *\nFROM foo\nWHERE x", true, // x column error
		},
		{
			27, 5, 7, "SELECT *\n\nFROM foo\n\nWHERE x", true, // x column error, empty lines
		},
		{
			10, 2, 1, "SELECT *\nFROMM foo", true, // FROMM typo
		},
		{
			11, 3, 1, "SELECT *\n\nFROMM foo", true, // FROMM typo, empty line
		},
		{
			17, 2, 8, "SELECT *\nFROM foo", true, // last character
		},
		{
			18, 0, 0, "SELECT *\nFROM foo", false, // invalid position
		},
	}
	for i, tc := range testcases {
		t.Run("tc"+strconv.Itoa(i), func(t *testing.T) {
			run := func(crlf bool, nonASCII bool) {
				var name string
				if crlf {
					name = "crlf"
				} else {
					name = "lf"
				}
				if nonASCII {
					name += "-nonascii"
				} else {
					name += "-ascii"
				}
				t.Run(name, func(t *testing.T) {
					input := tc.input
					if crlf {
						input = strings.Replace(input, "\n", "\r\n", -1)
					}
					if nonASCII {
						input = strings.Replace(input, "FROM", "FRÖM", -1)
					}
					gotLine, gotCol, gotOK := computeLineFromPos(input, tc.pos)

					if tc.wantOk {
						t.Logf("pos %d, want %d:%d, %#v", tc.pos, tc.wantLine, tc.wantCol, input)
					}

					if gotOK != tc.wantOk {
						t.Fatalf("expected ok %v but got %v", tc.wantOk, gotOK)
					}
					if gotLine != tc.wantLine {
						t.Fatalf("expected line %d but got %d", tc.wantLine, gotLine)
					}
					if gotCol != tc.wantCol {
						t.Fatalf("expected col %d but got %d", tc.wantCol, gotCol)
					}
				})
			}
			run(false, false)
			run(true, false)
			run(false, true)
			run(true, true)
		})
	}
}
