package db

import (
	"testing"
)

func TestOpen(t *testing.T) {
	cleanup, url, _, err := StartDbInDocker("postgres")
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Open(tt.args.dbType, tt.args.connectionUrl)
			defer func() {
				if err == nil {
					got.Close()
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

func TestMigrate(t *testing.T) {
	cleanup, url, _, err := StartDbInDocker("postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	type args struct {
		connectionUrl       string
		migrationsDirectory string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				connectionUrl:       url,
				migrationsDirectory: "migrations/postgres",
			},
			wantErr: false,
		},
		{
			name: "bad-url",
			args: args{
				connectionUrl:       "",
				migrationsDirectory: "migrations/postgres",
			},
			wantErr: true,
		},
		{
			name: "bad-dir",
			args: args{
				connectionUrl:       url,
				migrationsDirectory: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Migrate(tt.args.connectionUrl, tt.args.migrationsDirectory); (err != nil) != tt.wantErr {
				t.Errorf("Migrate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
