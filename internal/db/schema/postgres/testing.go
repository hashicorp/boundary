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
package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/stretchr/testify/require"
)

// Test runs tests against database implementations.
func Test(t *testing.T, d *Postgres, migration []byte) {
	if migration == nil {
		t.Fatal("test must provide migration reader")
	}

	TestNilVersion(t, d) // test first
	TestLockAndUnlock(t, d)
	TestRun(t, d, bytes.NewReader(migration))
	TestSetVersion(t, d) // also tests Version()
	// drop breaks the driver, so test it last.
	TestDrop(t, d)
}

func TestNilVersion(t *testing.T, d *Postgres) {
	ctx := context.TODO()
	v, _, err := d.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != database.NilVersion {
		t.Fatalf("Version: expected Version to be NilVersion (-1), got %v", v)
	}
}

func TestLockAndUnlock(t *testing.T, d *Postgres) {
	ctx := context.TODO()

	ctx, _ = context.WithTimeout(ctx, 15*time.Second)

	// locking twice is ok, no error
	if err := d.Lock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}
	if err := d.Lock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}

	// Unlock
	if err := d.Unlock(ctx); err != nil {
		t.Fatalf("error unlocking: %v", err)
	}

	// try to Lock
	if err := d.Lock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}
	if err := d.Unlock(ctx); err != nil {
		t.Fatalf("got error, expected none: %v", err)
	}

}

func TestRun(t *testing.T, d *Postgres, migration io.Reader) {
	ctx := context.TODO()
	if migration == nil {
		t.Fatal("migration can't be nil")
	}

	if err := d.Run(ctx, migration); err != nil {
		t.Fatal(err)
	}
}

func TestDrop(t *testing.T, d *Postgres) {
	ctx := context.TODO()
	if err := d.drop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSetVersion(t *testing.T, d *Postgres) {
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
			err := d.SetVersion(ctx, tc.version, tc.dirty)
			if err != tc.expectedErr {
				t.Fatal("Got unexpected error:", err, "!=", tc.expectedErr)
			}
			v, dirty, readErr := d.Version(ctx)
			if readErr != tc.expectedReadErr {
				t.Fatal("Got unexpected error:", readErr, "!=", tc.expectedReadErr)
			}
			if v != tc.expectedVersion {
				t.Error("Got unexpected Version:", v, "!=", tc.expectedVersion)
			}
			if dirty != tc.expectedDirty {
				t.Error("Got unexpected dirty value:", dirty, "!=", tc.dirty)
			}
		})
	}
}

func (p *Postgres) open(t *testing.T, ctx context.Context, u string) (*Postgres, error) {
	t.Helper()
	db, err := sql.Open("postgres", u)
	require.NoError(t, err)

	px, err := NewPostgres(ctx, db)
	require.NoError(t, err)

	return px, nil
}

func (p *Postgres) close(t *testing.T) error {
	t.Helper()
	require.NoError(t, p.conn.Close())
	require.NoError(t, p.db.Close())
	return nil
}
