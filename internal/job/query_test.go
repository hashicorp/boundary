package job

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
)

func TestFetchWorkQuery(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	testJob(t, conn, "job1", "code", "description")
	testJob(t, conn, "job2", "code", "description")
	wait1 := make(chan struct{})
	wait2 := make(chan struct{})
	ready1 := make(chan struct{})
	ready2 := make(chan struct{})
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		w := db.New(conn)
		count, err := testFetchWork(wait1, ready1, w)
		require.NoError(err)
		assert.Equal(1, count)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		w := db.New(conn)
		count, err := testFetchWork(wait2, ready2, w)
		require.NoError(err)
		assert.Equal(1, count)
		wg.Done()
	}()

	// Wait for above goroutines to be in transaction after querying for work
	<-ready1
	<-ready2

	// There are only two jobs and both are in currently being assigned to other servers.
	// An attempt to fetch work should return no work and not block on the request.
	w := db.New(conn)
	count, _ := testFetchWork(nil, nil, w)
	assert.Equal(0, count)

	// Let the transactions exit
	wait1 <- struct{}{}
	wait2 <- struct{}{}

	// Wait for above goroutines to verify test results
	wg.Wait()

	// FetchWork should return work again now that the transaction row locks have been released
	w = db.New(conn)
	count, _ = testFetchWork(nil, nil, w)
	assert.Equal(1, count)
}

func testFetchWork(wait <-chan struct{}, ready chan<- struct{}, w *db.Db) (int, error) {
	var rowCnt int
	_, err := w.DoTx(context.Background(), db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(context.Background(), fetchWorkQuery, nil)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				rowCnt += 1
				j := allocJob()
				err = r.ScanRows(rows, j)
				if err != nil {
					return err
				}
			}

			if ready != nil {
				// Notify caller we are waiting
				ready <- struct{}{}
			}

			if wait != nil {
				// Wait holding the transaction until signaled to exit
				<-wait
			}

			return nil
		},
	)
	if err != nil {
		return 0, err
	}
	return rowCnt, nil
}
