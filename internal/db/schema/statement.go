package schema

import (
	"fmt"
	"sort"

	"github.com/hashicorp/boundary/internal/errors"
)

// statementProvider provides the migration statements in order.
// Next should be called prior to calling Version() or ReadUp() or sentinel
// values (-1 and nil) will be returned.
type statementProvider struct {
	pos      int
	versions []int
	up, down map[int][]byte
}

func newStatementProvider(dialect string, curVer int) (*statementProvider, error) {
	op := errors.Op("schema.newStatementProvider")
	qp := statementProvider{pos: -1}
	qp.up, qp.down = getUpMigration(dialect), getDownMigration(dialect)
	if len(qp.up) != len(qp.down) {
		return nil, errors.New(errors.MigrationData, op, fmt.Sprintf("Mismatch up/down size: up %d vs. down %d", len(qp.up), len(qp.down)))
	}
	for k := range qp.up {
		if _, ok := qp.down[k]; !ok {
			return nil, errors.New(errors.MigrationData, op, fmt.Sprintf("Up key %d doesn't exist in down %v", k, qp.down))
		}
		qp.versions = append(qp.versions, k)
	}
	sort.Ints(qp.versions)

	for len(qp.versions) > 0 && qp.versions[0] <= curVer {
		qp.versions = qp.versions[1:]
	}

	return &qp, nil
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
func (q *statementProvider) ReadUp() []byte {
	if q.pos < 0 || q.pos >= len(q.versions) {
		return nil
	}
	return q.up[q.versions[q.pos]]
}
