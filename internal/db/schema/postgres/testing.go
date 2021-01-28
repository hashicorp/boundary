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

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// test runs tests against database implementations.
func test(t *testing.T, d *Postgres, migration []byte) {
	if migration == nil {
		t.Fatal("test must provide migration reader")
	}
	ctx := context.Background()

	v, alreadyRan, dirty, err := d.CurrentState(ctx)
	require.NoError(t, err)
	assert.False(t, alreadyRan)
	assert.False(t, dirty)
	assert.Equal(t, nilVersion, v)

	testLockAndUnlock(t, d)
	assert.NoError(t, d.EnsureVersionTable(ctx))
	assert.NoError(t, d.Run(ctx, bytes.NewReader(migration), 1))

	testSetVersion(t, d) // also tests CurrentState()
	// drop breaks the driver, so test it last.
	assert.NoError(t, d.drop(ctx))
}

func testLockAndUnlock(t *testing.T, d *Postgres) {
	ctx := context.Background()

	ctx, _ = context.WithTimeout(ctx, 15*time.Second)

	// locking twice is ok, no error
	require.NoError(t, d.Lock(ctx))
	assert.NoError(t, d.Lock(ctx))

	// Unlock
	assert.NoError(t, d.Unlock(ctx))

	// try to Lock
	assert.NoError(t, d.Lock(ctx))
	assert.NoError(t, d.Unlock(ctx))
}

func testSetVersion(t *testing.T, d *Postgres) {
	ctx := context.Background()
	require.NoError(t, d.EnsureVersionTable(ctx))
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
			// d.EnsureVersionTable(ctx)
			err := d.setVersion(ctx, tc.version, tc.dirty)
			if err != tc.expectedErr {
				t.Fatal("Got unexpected error:", err, "!=", tc.expectedErr)
			}
			v, _, dirty, readErr := d.CurrentState(ctx)
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

func open(t *testing.T, ctx context.Context, u string) (*Postgres, error) {
	t.Helper()
	db, err := sql.Open("postgres", u)
	require.NoError(t, err)

	px, err := New(ctx, db)
	require.NoError(t, err)

	return px, nil
}

func (p *Postgres) close(t *testing.T) error {
	t.Helper()
	require.NoError(t, p.conn.Close())
	require.NoError(t, p.db.Close())
	return nil
}
