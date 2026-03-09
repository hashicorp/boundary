// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	ctx := context.Background()
	cleanup, url, _, err := dbtest.StartUsingTemplate(dbtest.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	type args struct {
		dbType        DbType
		connectionUrl string
		opt           []Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				dbType:        Postgres,
				connectionUrl: url,
			},
			wantErr: false,
		},
		{
			name: "invalid",
			args: args{
				dbType:        Postgres,
				connectionUrl: "",
			},
			wantErr: true,
		},
		{
			name: "invalid - max_open_connections set to 3",
			args: args{
				dbType:        Postgres,
				connectionUrl: "",
				opt:           []Option{WithMaxOpenConnections(3)},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Open(ctx, tt.args.dbType, tt.args.connectionUrl)
			defer func() {
				if err == nil {
					sqlDB, err := got.SqlDB(ctx)
					require.NoError(t, err)
					err = sqlDB.Close()
					require.NoError(t, err)
				}
			}()
			if (err != nil) != tt.wantErr {
				t.Errorf("Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && got != nil {
				t.Error("Open() wanted error and got != nil")
			}
		})
	}
}

func TestSwap(t *testing.T) {
	tests := []struct {
		name      string
		db        func() *DB
		newDB     func() *DB
		expErr    bool
		expErrStr string
	}{
		{
			name: "nilNewDB",
			db: func() *DB {
				ret := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
				return ret
			},
			newDB:     nil,
			expErr:    true,
			expErrStr: "no new db object present",
		},
		{
			name: "nilNewDBWrapped",
			db: func() *DB {
				ret := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
				return ret
			},
			newDB: func() *DB {
				ret := &DB{}
				return ret
			},
			expErr:    true,
			expErrStr: "no new db object present",
		},
		{
			name: "nilCurrentDBWrapped",
			db: func() *DB {
				ret := &DB{}
				return ret
			},
			newDB: func() *DB {
				db, _ := dbw.TestSetupWithMock(t)
				ret := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
				ret.wrapped.Store(db)
				return ret
			},
			expErr:    true,
			expErrStr: "no current db is present to swap, aborting",
		},
		{
			name: "dbReplace",
			db: func() *DB {
				db, _ := dbw.TestSetupWithMock(t)
				ret := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
				ret.wrapped.Store(db)
				return ret
			},
			newDB: func() *DB {
				db, _ := dbw.TestSetupWithMock(t)
				ret := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
				ret.wrapped.Store(db)
				return ret
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var oldDb, newDb *DB
			if tt.db != nil {
				oldDb = tt.db()
			}
			if tt.newDB != nil {
				newDb = tt.newDB()
			}
			var oldWrappedVal dbw.DB
			if !tt.expErr {
				oldWrappedVal = *oldDb.wrapped.Load()
			}

			ctx := context.Background()
			closeFn, err := oldDb.Swap(ctx, newDb)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, closeFn)
				return
			}

			dbw.TestSetupWithMock(t)
			require.NoError(t, err)
			require.NotNil(t, closeFn)

			require.NotEqual(t, oldWrappedVal, oldDb.wrapped.Load())
			require.EqualValues(t, newDb.wrapped.Load(), oldDb.wrapped.Load()) // For pointer values, require tests the underlying values' equality.
		})
	}
}
