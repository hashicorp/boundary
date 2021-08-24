package schema

import (
	"sort"

	"github.com/hashicorp/boundary/internal/db/schema/migrations"
)

// statementProvider provides the migration statements in order.
// Next should be called prior to calling Version() or ReadUp() or sentinel
// values (-1 and nil) will be returned.
type statementProvider struct {
	pos      int
	versions []int
	up       map[int]migrations.UpVersion
}

func newStatementProvider(dialect string, curVer int, opt ...Option) *statementProvider {
	const op = "schema.newStatementProvider"
	qp := statementProvider{pos: -1}
	qp.up = getUpMigration(dialect, opt...)
	for k := range qp.up {
		qp.versions = append(qp.versions, k)
	}
	sort.Ints(qp.versions)

	for len(qp.versions) > 0 && qp.versions[0] <= curVer {
		qp.versions = qp.versions[1:]
	}

	return &qp
}

func (q *statementProvider) Next() bool {
	q.pos++
	return len(q.versions) > q.pos
}

func (q *statementProvider) Version() int {
	if q.pos < 0 || q.pos >= len(q.versions) {
		return -1
	}
	return q.versions[q.pos]
}

// ReadUp reads the current up migration
func (q *statementProvider) ReadUp() *migrations.UpVersion {
	if q.pos < 0 || q.pos >= len(q.versions) {
		return nil
	}
	ver := q.up[q.versions[q.pos]]
	return &ver
}
