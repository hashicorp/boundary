package db

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/testing/dbtest"
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
