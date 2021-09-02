package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

// A typeless plugin used for tests.
type plugin struct {
	*store.Plugin
	tableName string `gorm:"-"`
}

// newPlugin is used in tests and creates a typeless plugin in the global scope.
func newPlugin(name string, _ ...Option) *plugin {
	p := &plugin{
		Plugin: &store.Plugin{
			ScopeId: scope.Global.String(),
			Name:    name,
		},
	}
	return p
}

// TableName returns the table name for the host plugin.
func (c *plugin) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "plugin"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *plugin) SetTableName(n string) {
	c.tableName = n
}

func testPlugin(t *testing.T, conn *gorm.DB, name string) *plugin {
	t.Helper()
	p := newPlugin(name)
	id, err := db.NewPublicId("plg")
	require.NoError(t, err)
	p.PublicId = id

	w := db.New(conn)
	require.NoError(t, w.Create(context.Background(), p))
	return p
}
