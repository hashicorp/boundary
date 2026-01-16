// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteTermiantedSessionsJob(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
	require.NoError(t, err)

	cases := []struct {
		sessionCount   int
		terminateCount int
		threshold      time.Duration
		expected       int
	}{
		{0, 0, time.Nanosecond, 0},
		{1, 1, time.Nanosecond, 1},
		{1, 1, time.Hour, 0},
		{10, 10, time.Nanosecond, 10},
		{10, 4, time.Nanosecond, 4},
		{10, 0, time.Nanosecond, 0},
		{10, 10, time.Hour, 0},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_%d_%s", tc.sessionCount, tc.terminateCount, tc.threshold), func(t *testing.T) {
			t.Cleanup(func() {
				sdb, err := conn.SqlDB(ctx)
				require.NoError(t, err)
				_, err = sdb.Exec(`delete from session;`)
				require.NoError(t, err)
			})

			for i := 0; i < tc.sessionCount; i++ {
				s := TestSession(t, conn, wrapper, composedOf)
				if i < tc.terminateCount {
					_, err = repo.CancelSession(ctx, s.PublicId, s.Version)
					require.NoError(t, err)
				}

			}
			c, err := repo.TerminateCompletedSessions(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.terminateCount, c)

			job, err := newDeleteTerminatedJob(ctx, repo, tc.threshold)
			require.NoError(t, err)
			err = job.Run(ctx, 1*time.Second)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, job.Status().Completed)
		})
	}
}
