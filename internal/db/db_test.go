package db

import (
	"context"
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
		db        *DB
		newDB     *DB
		expErr    bool
		expErrStr string
	}{
		{
			name:      "nilNewDB",
			db:        &DB{wrapped: &dbw.DB{}},
			newDB:     nil,
			expErr:    true,
			expErrStr: "no new db object present",
		},
		{
			name:      "nilNewDBWrapped",
			db:        &DB{wrapped: &dbw.DB{}},
			newDB:     &DB{wrapped: nil},
			expErr:    true,
			expErrStr: "no new db object present",
		},
		{
			name:      "nilCurrentDBWrapped",
			db:        &DB{wrapped: nil},
			newDB:     &DB{wrapped: &dbw.DB{}},
			expErr:    true,
			expErrStr: "no current db is present to swap, aborting",
		},
		{
			name: "dbReplace",
			db: &DB{wrapped: func() *dbw.DB {
				db, _ := dbw.TestSetupWithMock(t)
				return db
			}()},
			newDB: &DB{wrapped: func() *dbw.DB {
				db, _ := dbw.TestSetupWithMock(t)
				return db
			}()},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var oldWrappedPtr *dbw.DB
			var oldWrappedVal dbw.DB
			if !tt.expErr {
				oldWrappedPtr = tt.db.wrapped
				oldWrappedVal = *tt.db.wrapped
			}

			ctx := context.Background()
			closeFn, err := tt.db.Swap(ctx, tt.newDB)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, closeFn)
				return
			}

			dbw.TestSetupWithMock(t)
			require.NoError(t, err)
			require.NotNil(t, closeFn)

			// Assert that the `wrapped` pointer didn't change, but its value did.
			if oldWrappedPtr != tt.db.wrapped {
				t.Fatalf("expected pointers to not have changed, but they did. old ptr: %p, new ptr %p", oldWrappedVal, tt.db.wrapped)
			}
			require.NotEqual(t, oldWrappedVal, tt.db.wrapped)
			require.EqualValues(t, tt.newDB.wrapped, tt.db.wrapped) // For pointer values, require tests the underlying values' equality.
		})
	}
}
