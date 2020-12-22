package schema

import (
	"fmt"
	"sort"

	"github.com/hashicorp/boundary/internal/db/schema/postgres"
)

type statementProvider struct {
	pos      int
	versions []int
	up, down map[int][]byte
}

func newStatementProvider(dialect string, curVer int) statementProvider {
	qp := statementProvider{pos: -1}
	qp.up, qp.down = postgres.UpMigrations, postgres.DownMigrations
	if len(qp.up) != len(qp.down) {
		fmt.Printf("Mismatch up/down size: up %d vs. down %d", len(qp.up), len(qp.down))
	}
	for k := range qp.up {
		if _, ok := qp.down[k]; !ok {
			fmt.Printf("Up key %d doesn't exist in down %v", k, qp.down)
		}
		qp.versions = append(qp.versions, k)
	}
	sort.Ints(qp.versions)

	for len(qp.versions) > 0 && qp.versions[0] <= curVer {
		qp.versions = qp.versions[1:]
	}

	return qp
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
