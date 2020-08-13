package static

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/host/static/store"
)

func TestHostCatalog_SetTableName(t *testing.T) {
	defaultTableName := "static_host_catalog"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocCatalog()
			require.Equal(defaultTableName, def.TableName())
			s := &HostCatalog{
				HostCatalog: &store.HostCatalog{},
				tableName:   tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestHost_SetTableName(t *testing.T) {
	defaultTableName := "static_host"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &Host{
				Host: &store.Host{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &Host{
				Host:      &store.Host{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestHostSet_SetTableName(t *testing.T) {
	defaultTableName := "static_host_set"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &HostSet{
				HostSet: &store.HostSet{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &HostSet{
				HostSet:   &store.HostSet{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestHostSetMember_SetTableName(t *testing.T) {
	defaultTableName := "static_host_set_member"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &HostSetMember{
				HostSetMember: &store.HostSetMember{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &HostSetMember{
				HostSetMember: &store.HostSetMember{},
				tableName:     tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
