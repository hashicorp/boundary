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

// Package testing has the database tests.
// All database drivers must pass the Test function.
// This lives in it's own package so it stays a test dependency.
package schema

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/hashicorp/boundary/internal/errors"
)

// Test runs tests against database implementations.
func Test(t *testing.T, d *postgres, migration []byte) {
	if migration == nil {
		t.Fatal("test must provide migration reader")
	}

	TestNilVersion(t, d) // test first
	TestLockAndUnlock(t, d)
	TestRun(t, d, bytes.NewReader(migration))
	TestSetVersion(t, d) // also tests version()
	// drop breaks the driver, so test it last.
	TestDrop(t, d)
}

func TestNilVersion(t *testing.T, d *postgres) {
	ctx := context.TODO()
	v, _, err := d.version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != database.NilVersion {
		t.Fatalf("version: expected version to be NilVersion (-1), got %v", v)
	}
}

func TestLockAndUnlock(t *testing.T, d *postgres) {
	ctx := context.TODO()

	ctx, _ = context.WithTimeout(ctx, 15*time.Second)

	// locking twice is ok, no error
	if err := d.lock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}
	if err := d.lock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}

	// unlock
	if err := d.unlock(ctx); err != nil {
		t.Fatalf("error unlocking: %v", err)
	}

	// try to lock
	if err := d.lock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}
	if err := d.unlock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}

}

func TestRun(t *testing.T, d *postgres, migration io.Reader) {
	ctx := context.TODO()
	if migration == nil {
		t.Fatal("migration can't be nil")
	}

	if err := d.run(ctx, migration); err != nil {
		t.Fatal(err)
	}
}

func TestDrop(t *testing.T, d *postgres) {
	ctx := context.TODO()
	if err := d.drop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSetVersion(t *testing.T, d *postgres) {
	ctx := context.TODO()
	// nolint:maligned
	testCases := []struct {
		name            string
		version         int
		dirty           bool
		expectedErr     error
		expectedReadErr error
		expectedVersion int
		expectedDirty   bool
	}{
		{name: "set 1 dirty", version: 1, dirty: true, expectedErr: nil, expectedReadErr: nil, expectedVersion: 1, expectedDirty: true},
		{name: "re-set 1 dirty", version: 1, dirty: true, expectedErr: nil, expectedReadErr: nil, expectedVersion: 1, expectedDirty: true},
		{name: "set 2 clean", version: 2, dirty: false, expectedErr: nil, expectedReadErr: nil, expectedVersion: 2, expectedDirty: false},
		{name: "re-set 2 clean", version: 2, dirty: false, expectedErr: nil, expectedReadErr: nil, expectedVersion: 2, expectedDirty: false},
		{name: "last migration dirty", version: database.NilVersion, dirty: true, expectedErr: nil, expectedReadErr: nil, expectedVersion: database.NilVersion, expectedDirty: true},
		{name: "last migration clean", version: database.NilVersion, dirty: false, expectedErr: nil, expectedReadErr: nil, expectedVersion: database.NilVersion, expectedDirty: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := d.setVersion(ctx, tc.version, tc.dirty)
			if err != tc.expectedErr {
				t.Fatal("Got unexpected error:", err, "!=", tc.expectedErr)
			}
			v, dirty, readErr := d.version(ctx)
			if readErr != tc.expectedReadErr {
				t.Fatal("Got unexpected error:", readErr, "!=", tc.expectedReadErr)
			}
			if v != tc.expectedVersion {
				t.Error("Got unexpected version:", v, "!=", tc.expectedVersion)
			}
			if dirty != tc.expectedDirty {
				t.Error("Got unexpected dirty value:", dirty, "!=", tc.dirty)
			}
		})
	}
}

func (p *postgres) open(ctx context.Context, u string) (*postgres, error) {
	const op = "schema.(postgres).open"
	db, err := sql.Open("postgres", u)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	px, err := newPostgres(ctx, db)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	return px, nil
}

func (p *postgres) close() error {
	connErr := p.conn.Close()
	dbErr := p.db.Close()
	if connErr != nil || dbErr != nil {
		return fmt.Errorf("conn: %v, db: %v", connErr, dbErr)
	}
	return nil
}
