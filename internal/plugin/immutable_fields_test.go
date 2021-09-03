package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPlugin_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	plg := testPlugin(t, conn, "test")

	newPlugin := plg

	tests := []struct {
		name      string
		update    *plugin
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *plugin {
				c := newPlugin.testClonePlugin()
				c.PublicId = "pi_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "scope",
			update: func() *plugin {
				c := newPlugin.testClonePlugin()
				c.ScopeId = "o_1234567890"
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := newPlugin.testClonePlugin()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := newPlugin.testClonePlugin()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func (c *plugin) testClonePlugin() *plugin {
	cp := proto.Clone(c.Plugin)
	return &plugin{
		Plugin: cp.(*store.Plugin),
	}
}
