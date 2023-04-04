// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
)

// A typeless plugin used for tests.
type plugin struct {
	*store.Plugin
	tableName string `gorm:"-"`
}

// newPlugin is used in tests and creates a typeless plugin in the global scope.
func newPlugin(name string) *plugin {
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

// getTestOpts - iterate the inbound TestOptions and return a struct
func getTestOpts(opt ...TestOption) testOptions {
	opts := getDefaultTestOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// TestOption - how Options are passed as arguments
type TestOption func(*testOptions)

// options = how options are represented
type testOptions struct {
	withHostFlag bool
}

func getDefaultTestOptions() testOptions {
	return testOptions{
		withHostFlag: true,
	}
}

// WithHostFlag determines whether or not to enable the host flag for a test plugin
func WithHostFlag(flag bool) TestOption {
	return func(o *testOptions) {
		o.withHostFlag = flag
	}
}

// TestPlugin creates a plugin and inserts it into the database. enables the "host" flag by default
func TestPlugin(t testing.TB, conn *db.DB, name string, opt ...TestOption) *Plugin {
	opts := getTestOpts(opt...)
	t.Helper()
	p := NewPlugin(WithName(name))
	id, err := newPluginId()
	require.NoError(t, err)
	p.PublicId = id

	w := db.New(conn)
	require.NoError(t, w.Create(context.Background(), p))

	if opts.withHostFlag {
		// add the host supported flag
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(w, w, kmsCache)
		require.NoError(t, err)
		repo.AddSupportFlag(context.Background(), p, PluginTypeHost)
	}

	return p
}
