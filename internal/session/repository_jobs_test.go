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

func TestRepository_getDeleteJobParams(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	const defaultBatchSize = 5000

	cases := []struct {
		sessionCount          int
		terminateCount        int
		threshold             time.Duration
		expectedBatchSize     int
		expectedTotalToDelete int
	}{
		{0, 0, time.Nanosecond, defaultBatchSize, 0},
		{1, 1, time.Nanosecond, defaultBatchSize, 1},
		{1, 1, time.Hour, defaultBatchSize, 0},
		{10, 10, time.Nanosecond, defaultBatchSize, 10},
		{10, 4, time.Nanosecond, defaultBatchSize, 4},
		{10, 0, time.Nanosecond, defaultBatchSize, 0},
		{10, 10, time.Hour, defaultBatchSize, 0},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_%d_%s_%d", tc.sessionCount, tc.terminateCount, tc.threshold, tc.expectedBatchSize), func(t *testing.T) {
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

			p, err := repo.getDeleteJobParams(ctx, tc.threshold)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedBatchSize, p.BatchSize)
			assert.Equal(t, tc.expectedTotalToDelete, p.TotalToDelete)
		})
	}
}

func TestRepository_deleteTerminatedSessionsBatch(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	cases := []struct {
		sessionCount   int
		terminateCount int
		batchSize      int
		expected       int
	}{
		{0, 0, 10, 0},
		{1, 1, 10, 1},
		{10, 10, 5, 5},
		{10, 2, 5, 2},
		{10, 0, 10, 0},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_%d_%d", tc.sessionCount, tc.terminateCount, tc.batchSize), func(t *testing.T) {
			t.Cleanup(func() {
				sdb, err := conn.SqlDB(ctx)
				require.NoError(t, err)
				_, err = sdb.Exec(`delete from session;`)
				require.NoError(t, err)
			})

			// add initial group of sessions and terminate some of them
			{
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
			}

			// get the job parameters
			p, err := repo.getDeleteJobParams(ctx, time.Nanosecond)
			require.NoError(t, err)
			assert.Equal(t, tc.terminateCount, p.TotalToDelete)

			// add more sessions to test the WindowStartTime
			{
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
			}

			c, err := repo.deleteTerminatedSessionsBatch(ctx, p.WindowStartTime, tc.batchSize)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, c)
		})
	}
}

func TestRepository_setDeleteJobBatchSize(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)

	cases := []struct {
		batchSize int
		expectErr bool
	}{
		{-1, true},
		{0, true},
		{1, false},
		{9, false},
		{10, false},
		{10000, false},
		{10001, false},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_%t", tc.batchSize, tc.expectErr), func(t *testing.T) {
			err = repo.setDeleteJobBatchSize(ctx, tc.batchSize)
			if tc.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			p, err := repo.getDeleteJobParams(ctx, time.Nanosecond)
			require.NoError(t, err)
			assert.Equal(t, tc.batchSize, p.BatchSize)
		})
	}
}
