package host_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetWrapper_SetTableName(t *testing.T) {
	defaultTableName := "host_set"
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
			def := &host.SetWrapper{
				Set: &store.Set{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &host.SetWrapper{
				Set: &store.Set{},
			}
			s.SetTableName(tt.initialName)
			if tt.initialName == "" {
				assert.Equal(defaultTableName, s.TableName())
			} else {
				assert.Equal(tt.initialName, s.TableName())
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
