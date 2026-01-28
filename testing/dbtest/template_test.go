// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package dbtest_test

import (
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

func TestStartUsingTemplate(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		options []dbtest.Option
		err     error
	}{
		{
			"PostgresNoOptions",
			dbtest.Postgres,
			[]dbtest.Option{},
			nil,
		},
		{
			"PostgresTemplate1",
			dbtest.Postgres,
			[]dbtest.Option{
				dbtest.WithTemplate(dbtest.Template1),
			},
			nil,
		},
		{
			"PostgresUnsupportedTemplate",
			dbtest.Postgres,
			[]dbtest.Option{
				dbtest.WithTemplate("unsupportedTemplate"),
			},
			errors.New("unsupported database template: unsupportedTemplate"),
		},
		{
			"UnsupportedDialect",
			"unsupportedDialect",
			[]dbtest.Option{},
			errors.New("unsupported dialect: unsupportedDialect"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, u, _, err := dbtest.StartUsingTemplate(tt.dialect, tt.options...)

			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
				require.NoError(t, c())
			} else {
				require.NoError(t, err)

				db, err := common.SqlOpen(tt.dialect, u)
				require.NoError(t, err)
				require.NoError(t, db.Ping())
				db.Close()

				require.NoError(t, c())

				// ensure that database is gone after calling c
				db, _ = common.SqlOpen(tt.dialect, u)
				require.Error(t, db.Ping())
			}
		})
	}
}
