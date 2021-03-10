package database

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateDatabase(t *testing.T) {
	ctx := context.Background()
	dialect := "postgres"

	cases := []struct {
		name           string
		requireFresh   bool
		urlProvider    func() string
		expectedCode   int
		expectedOutput string
		expectedError  string
	}{
		{
			name: "basic",
			urlProvider: func() string {
				c, u, _, err := db.StartDbInDocker(dialect)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, c())
				})
				return u
			},
			expectedCode:   0,
			expectedOutput: "Migrations successfully run.\n",
		},
		{
			name: "old_version_table_used",
			urlProvider: func() string {
				c, u, _, err := db.StartDbInDocker(dialect)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, c())
				})
				dBase, err := sql.Open(dialect, u)
				require.NoError(t, err)

				createStmt := `create table if not exists schema_migrations (version bigint primary key, dirty boolean not null)`
				_, err = dBase.Exec(createStmt)
				require.NoError(t, err)
				return u
			},
			expectedCode:   0,
			expectedOutput: "Migrations successfully run.\n",
		},
		{
			name:          "bad_url",
			urlProvider:   func() string { return "badurl" },
			expectedCode:  2,
			expectedError: "Unable to connect to the database at \"badurl\"\n",
		},
		{
			name: "cant_get_lock",
			urlProvider: func() string {
				c, u, _, err := db.StartDbInDocker(dialect)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, c())
				})
				dBase, err := sql.Open(dialect, u)
				require.NoError(t, err)

				man, err := schema.NewManager(ctx, dialect, dBase)
				require.NoError(t, err)
				// This is an advisory lock on the DB which is released when the DB session ends.
				err = man.ExclusiveLock(ctx)
				require.NoError(t, err)

				return u
			},
			expectedCode:  2,
			expectedError: "Unable to capture a lock on the database.\n",
		},
		{
			name:         "basic_require_fresh",
			requireFresh: true,
			urlProvider: func() string {
				c, u, _, err := db.StartDbInDocker(dialect)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, c())
				})
				return u
			},
			expectedCode:   0,
			expectedOutput: "Migrations successfully run.\n",
		},
		{
			name:         "old_version_table_used_require_fresh",
			requireFresh: true,
			urlProvider: func() string {
				c, u, _, err := db.StartDbInDocker(dialect)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, c())
				})
				dBase, err := sql.Open(dialect, u)
				require.NoError(t, err)

				createStmt := `create table if not exists schema_migrations (version bigint primary key, dirty boolean not null)`
				_, err = dBase.Exec(createStmt)
				require.NoError(t, err)
				return u
			},
			expectedCode:  2,
			expectedError: "Database has already been initialized.  Please use 'boundary database\nmigrate'.\n",
		},
		{
			name:          "bad_url_require_fresh",
			requireFresh:  true,
			urlProvider:   func() string { return "badurl" },
			expectedCode:  2,
			expectedError: "Unable to connect to the database at \"badurl\"\n",
		},
		{
			name:         "cant_get_lock_require_fresh",
			requireFresh: true,
			urlProvider: func() string {
				c, u, _, err := db.StartDbInDocker(dialect)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, c())
				})
				dBase, err := sql.Open(dialect, u)
				require.NoError(t, err)

				man, err := schema.NewManager(ctx, dialect, dBase)
				require.NoError(t, err)
				// This is an advisory lock on the DB which is released when the DB session ends.
				err = man.ExclusiveLock(ctx)
				require.NoError(t, err)

				return u
			},
			expectedCode:  2,
			expectedError: "Unable to capture a lock on the database.\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := tc.urlProvider()
			ui := cli.NewMockUi()
			clean, errCode := migrateDatabase(ctx, ui, dialect, u, tc.requireFresh)
			clean()
			assert.EqualValues(t, tc.expectedCode, errCode)
			assert.Equal(t, tc.expectedOutput, ui.OutputWriter.String())
			assert.Equal(t, tc.expectedError, ui.ErrorWriter.String())
		})
	}
}

func TestVerifyOplogIsEmpty(t *testing.T) {
	dialect := "postgres"
	ctx := context.Background()

	c, u, _, err := db.StartDbInDocker(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	_ = c

	dBase, err := sql.Open(dialect, u)
	require.NoError(t, err)

	man, err := schema.NewManager(ctx, dialect, dBase)
	require.NoError(t, err)
	require.NoError(t, man.RollForward(ctx))

	cmd := InitCommand{Command: base.NewCommand(cli.NewMockUi())}
	cmd.srv = base.NewServer(&base.Command{UI: cmd.UI})

	cmd.srv.DatabaseUrl = u
	require.NoError(t, cmd.srv.ConnectToDatabase(dialect))

	assert.NoError(t, cmd.verifyOplogIsEmpty())
}
