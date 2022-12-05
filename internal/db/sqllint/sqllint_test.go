package sqllint_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type invalid struct {
	constraintName string
	relName        string
}

func TestUniqueConstraintName(t *testing.T) {
	const check = `
select con.conname, rel.relname
  from       pg_catalog.pg_constraint con
  inner join pg_catalog.pg_class      rel
		on rel.oid = con.conrelid
  inner join pg_catalog.pg_namespace  nsp
		on nsp.oid = con.connamespace
  where
		nsp.nspname = 'public'
    and
		con.contype = 'u'
	and
		con.conname not like rel.relname::text || '_%_uq';
`
	ctx := context.Background()
	dialect := dbtest.Postgres
	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	rows, err := d.QueryContext(ctx, check)
	require.NoError(t, err)

	var failures []invalid
	for rows.Next() {
		var i invalid
		require.NoError(t, rows.Scan(&i.constraintName, &i.relName))
		failures = append(failures, i)
	}

	assert.Equal(t, failures, []invalid{})
}
