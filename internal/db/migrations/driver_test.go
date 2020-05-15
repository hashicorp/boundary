package migrations

import (
	"os"
	"reflect"
	"testing"

	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	"github.com/stretchr/testify/assert"
)

func TestNewMigrationSource(t *testing.T) {
	type args struct {
		dialect string
	}
	tests := []struct {
		name    string
		args    args
		want    source.Driver
		wantErr bool
	}{
		{
			name: "postgres",
			args: args{dialect: "postgres"},
			want: func() source.Driver {
				d, err := httpfs.New(&migrationDriver{"postgres"}, "migrations")
				if err != nil {
					t.Errorf("NewMigrationSource() error creating httpfs = %w", err)
				}
				return d
			}(),
			wantErr: false,
		},
		{
			name:    "no-dialect",
			args:    args{dialect: ""},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "bad-dialect",
			args:    args{dialect: "rainbows-and-unicorns-db"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewMigrationSource(tt.args.dialect)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMigrationSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewMigrationSource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_migrationDriver_Open(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		dialect string
		args    args
		wantErr bool
	}{
		{
			name:    "valid-file",
			dialect: "postgres",
			args:    args{name: "migrations/01_domain_types.up.sql"},
			wantErr: false,
		},
		{
			name:    "bad-file",
			dialect: "postgres",
			args:    args{name: "migrations/unicorns-and-rainbows.up.sql"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &migrationDriver{
				dialect: tt.dialect,
			}
			_, err := m.Open(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("migrationDriver.Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_fakeFile_Read(t *testing.T) {
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		ff, err := newFakeFile("postgres", "migrations/01_domain_types.up.sql")
		assert.Nil(err)
		buf := make([]byte, len(ff.bytes))
		n, err := ff.Read(buf)
		assert.Nil(err)
		assert.Equal(len(buf), n)
	})
}

func Test_fakeFile_Seek(t *testing.T) {
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		ff, err := newFakeFile("postgres", "migrations/01_domain_types.up.sql")
		assert.Nil(err)
		buf := make([]byte, len(ff.bytes))
		n, err := ff.Seek(10, 0)
		assert.Nil(err)
		assert.Equal(int64(10), n)

		n2, err := ff.Read(buf)
		assert.Nil(err)
		assert.Equal(len(ff.bytes)-10, n2)
	})
}

func Test_fakeFile_Close(t *testing.T) {
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		m := &migrationDriver{
			dialect: "postgres",
		}
		f, err := m.Open("migrations/01_domain_types.up.sql")
		assert.Nil(err)
		err = f.Close()
		assert.Nil(err)
	})
}

func Test_fakeFile_Stat(t *testing.T) {
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		name := "migrations/01_domain_types.up.sql"
		ff, err := newFakeFile("postgres", name)
		assert.Nil(err)
		info, err := ff.Stat()
		assert.Nil(err)
		assert.Equal(ff.name, info.Name())
		assert.Equal(int64(len(ff.bytes)), info.Size())
		assert.Equal(os.ModePerm, info.Mode())
		assert.Equal(false, info.IsDir())
		assert.Equal(nil, info.Sys())
	})
}

func Test_fakeFile_Readdir(t *testing.T) {
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		name := "migrations/01_domain_types.up.sql"
		ff, err := newFakeFile("postgres", name)
		assert.Nil(err)
		info, err := ff.Readdir(0)
		assert.Nil(err)
		assert.True(info != nil)

		info, err = ff.Readdir(1)
		assert.Nil(err)
		assert.True(info != nil)
		assert.Equal(1, len(info))

		info, err = ff.Readdir(0)
		assert.Nil(err)
		assert.True(info != nil)
		// we don't want to count "migrations", so we're len - 1
		assert.Equal(len(postgresMigrations)-1, len(info))
	})
}
