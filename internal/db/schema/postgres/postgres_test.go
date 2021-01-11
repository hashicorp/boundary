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
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dhui/dktest"
	"github.com/golang-migrate/migrate/v4/dktesting"
)

const (
	pgPassword = "postgres"
)

var (
	opts = dktest.Options{
		Env:          map[string]string{"POSTGRES_PASSWORD": pgPassword},
		PortRequired: true, ReadyFunc: isReady}
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
		ctx := context.TODO()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p := &Postgres{}
		d, err := p.open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Error(err)
			}
		}()
		Test(t, d, []byte("SELECT 1"))
	})
}

func TestMultiStatement(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.TODO()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p := &Postgres{}
		d, err := p.open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Error(err)
			}
		}()
		if err := d.Run(ctx, strings.NewReader("CREATE TABLE foo (foo text); CREATE TABLE bar (bar text);")); err != nil {
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

func TestWithSchema(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.TODO()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p := &Postgres{}
		d, err := p.open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d.close(t); err != nil {
				t.Fatal(err)
			}
		}()

		// create foobar schema
		if err := d.Run(ctx, strings.NewReader("CREATE SCHEMA foobar AUTHORIZATION postgres")); err != nil {
			t.Fatal(err)
		}
		if err := d.SetVersion(ctx, 1, false); err != nil {
			t.Fatal(err)
		}

		// re-connect using that schema
		d2, err := p.open(t, ctx, fmt.Sprintf("postgres://postgres:%s@%v:%v/postgres?sslmode=disable&search_path=foobar",
			pgPassword, ip, port))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := d2.close(t); err != nil {
				t.Fatal(err)
			}
		}()

		version, _, err := d2.Version(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if version != nilVersion {
			t.Fatal("expected NilVersion")
		}

		// now update Version and compare
		if err := d2.SetVersion(ctx, 2, false); err != nil {
			t.Fatal(err)
		}
		version, _, err = d2.Version(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if version != 2 {
			t.Fatal("expected Version 2")
		}

		// meanwhile, the public schema still has the other Version
		version, _, err = d.Version(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if version != 1 {
			t.Fatal("expected Version 2")
		}
	})
}

func TestPostgres_Lock(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ctx := context.TODO()
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		addr := pgConnectionString(ip, port)
		p := &Postgres{}
		ps, err := p.open(t, ctx, addr)
		if err != nil {
			t.Fatal(err)
		}

		Test(t, ps, []byte("SELECT 1"))

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
	})
}

func TestWithInstance_Concurrent(t *testing.T) {
	dktesting.ParallelTest(t, specs, func(t *testing.T, c dktest.ContainerInfo) {
		ip, port, err := c.FirstPort()
		if err != nil {
			t.Fatal(err)
		}

		// The number of concurrent processes running NewPostgres
		const concurrency = 30

		// We can instantiate a single database handle because it is
		// actually a connection pool, and so, each of the below go
		// routines will have a high probability of using a separate
		// connection, which is something we want to exercise.
		db, err := sql.Open("postgres", pgConnectionString(ip, port))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := db.Close(); err != nil {
				t.Error(err)
			}
		}()

		db.SetMaxIdleConns(concurrency)
		db.SetMaxOpenConns(concurrency)

		var wg sync.WaitGroup
		defer wg.Wait()

		wg.Add(concurrency)
		for i := 0; i < concurrency; i++ {
			go func(i int) {
				defer wg.Done()
				_, err := NewPostgres(context.TODO(), db)
				if err != nil {
					t.Errorf("process %d error: %s", i, err)
				}
			}(i)
		}
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
