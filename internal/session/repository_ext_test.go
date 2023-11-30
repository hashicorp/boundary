// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_ListSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	composedOf := session.TestSessionParams(t, conn, wrapper, iamRepo)

	listPerms := &perms.UserPermissions{
		UserId: composedOf.UserId,
		Permissions: []perms.Permission{
			{
				ScopeId:  composedOf.ProjectId,
				Resource: resource.Session,
				Action:   action.List,
			},
		},
	}
	type args struct {
		opt []session.Option
	}
	tests := []struct {
		name            string
		createCnt       int
		args            args
		perms           *perms.UserPermissions
		wantCnt         int
		wantErr         bool
		wantTTime       time.Time
		withConnections int
	}{
		{
			name:      "default-limit",
			createCnt: testLimit + 1,
			args:      args{},
			perms:     listPerms,
			wantCnt:   testLimit,
			wantErr:   false,
			wantTTime: time.Now(),
		},
		{
			name:      "custom-limit",
			createCnt: testLimit + 1,
			args: args{
				opt: []session.Option{session.WithLimit(3)},
			},
			perms:     listPerms,
			wantCnt:   3,
			wantErr:   false,
			wantTTime: time.Now(),
		},
		{
			name:      "withNoPerms",
			createCnt: testLimit + 1,
			args:      args{},
			perms:     &perms.UserPermissions{},
			wantCnt:   0,
			wantErr:   false,
			wantTTime: time.Time{},
		},
		{
			name:      "withPermsDifferentScopeId",
			createCnt: testLimit + 1,
			args:      args{},
			perms: &perms.UserPermissions{
				Permissions: []perms.Permission{
					{
						ScopeId:  "o_thisIsNotValid",
						Resource: resource.Session,
						Action:   action.List,
					},
				},
			},
			wantCnt:   0,
			wantErr:   false,
			wantTTime: time.Now(),
		},
		{
			name:      "withPermsNonListAction",
			createCnt: testLimit + 1,
			args:      args{},
			perms: &perms.UserPermissions{
				Permissions: []perms.Permission{
					{
						ScopeId:  composedOf.ProjectId,
						Resource: resource.Session,
						Action:   action.Read,
					},
				},
			},
			wantCnt:   0,
			wantErr:   false,
			wantTTime: time.Time{},
		},
		{
			name:            "multiple-connections",
			createCnt:       testLimit + 1,
			args:            args{},
			perms:           listPerms,
			wantCnt:         testLimit,
			wantErr:         false,
			withConnections: 3,
			wantTTime:       time.Now(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			repo, err := session.NewRepository(ctx, rw, rw, kms, session.WithLimit(testLimit), session.WithPermissions(tt.perms))
			require.NoError(err)

			db.TestDeleteWhere(t, conn, func() any { i := session.AllocSession(); return &i }(), "1=1")
			testSessions := []*session.Session{}
			for i := 0; i < tt.createCnt; i++ {
				s := session.TestSession(t, conn, wrapper, composedOf)
				_ = session.TestState(t, conn, s.PublicId, session.StatusActive)
				testSessions = append(testSessions, s)
				for i := 0; i < tt.withConnections; i++ {
					_ = session.TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.2", 23, "127.0.0.1")
				}
			}
			assert.Equal(tt.createCnt, len(testSessions))
			got, ttime := session.TestListSessions(t, repo, context.Background(), tt.args.opt...)
			assert.Equal(tt.wantCnt, len(got))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(tt.wantTTime.Before(ttime.Add(10 * time.Second)))
			assert.True(tt.wantTTime.After(ttime.Add(-10 * time.Second)))
			for i := 0; i < len(got); i++ {
				// connections should not be returned for list requests
				assert.Equal(0, len(got[i].Connections))
				for _, c := range got[i].Connections {
					assert.Equal("127.0.0.1", c.ClientTcpAddress)
					assert.Equal(uint32(22), c.ClientTcpPort)
					assert.Equal("127.0.0.2", c.EndpointTcpAddress)
					assert.Equal(uint32(23), c.EndpointTcpPort)
				}
			}
			if tt.wantCnt > 0 {
				assert.Equal(session.StatusActive, got[0].States[0].Status)
				assert.Equal(session.StatusPending, got[0].States[1].Status)
			}
		})
	}
	t.Run("onlySelf", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db.TestDeleteWhere(t, conn, func() any { i := session.AllocSession(); return &i }(), "1=1")
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = session.TestSession(t, conn, wrapper, composedOf)
		}
		s := session.TestDefaultSession(t, conn, wrapper, iamRepo)

		p := &perms.UserPermissions{
			UserId: s.UserId,
			Permissions: []perms.Permission{
				{
					ScopeId:  s.ProjectId,
					Resource: resource.Session,
					Action:   action.List,
					OnlySelf: true,
				},
			},
		}
		repo, err := session.NewRepository(ctx, rw, rw, kms, session.WithLimit(testLimit), session.WithPermissions(p))
		require.NoError(err)
		got, ttime := session.TestListSessions(t, repo, context.Background(), session.WithUserId(s.UserId))
		require.NoError(err)
		assert.Equal(1, len(got))
		assert.Equal(s.UserId, got[0].UserId)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db.TestDeleteWhere(t, conn, func() any { i := session.AllocSession(); return &i }(), "1=1")

		composedOf := session.TestSessionParams(t, conn, wrapper, iamRepo)

		listPerms := &perms.UserPermissions{
			UserId: composedOf.UserId,
			Permissions: []perms.Permission{
				{
					ScopeId:  composedOf.ProjectId,
					Resource: resource.Session,
					Action:   action.List,
				},
			},
		}

		for i := 0; i < 10; i++ {
			_ = session.TestSession(t, conn, wrapper, composedOf)
		}

		repo, err := session.NewRepository(ctx, rw, rw, kms, session.WithPermissions(listPerms))
		require.NoError(err)
		page1, ttime := session.TestListSessions(
			t,
			repo,
			context.Background(),
			session.WithLimit(2),
		)
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime := session.TestListSessions(
			t,
			repo,
			context.Background(),
			session.WithLimit(2),
			session.WithStartPageAfterItem(page1[1]),
		)
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime := session.TestListSessions(
			t,
			repo,
			context.Background(),
			session.WithLimit(2),
			session.WithStartPageAfterItem(page2[1]),
		)
		require.NoError(err)
		require.Len(page3, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, ttime := session.TestListSessions(
			t,
			repo,
			context.Background(),
			session.WithLimit(2),
			session.WithStartPageAfterItem(page3[1]),
		)
		require.NoError(err)
		require.Len(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, ttime := session.TestListSessions(
			t,
			repo,
			context.Background(),
			session.WithLimit(2),
			session.WithStartPageAfterItem(page4[1]),
		)
		require.NoError(err)
		require.Len(page5, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, ttime := session.TestListSessions(
			t,
			repo,
			context.Background(),
			session.WithLimit(2),
			session.WithStartPageAfterItem(page5[1]),
		)
		require.NoError(err)
		require.Empty(page6)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		// Cancel the first two sessions in lieu of updating
		_, err = repo.CancelSession(ctx, page1[0].PublicId, page1[0].Version)
		require.NoError(err)
		_, err = repo.CancelSession(ctx, page1[1].PublicId, page1[1].Version)
		require.NoError(err)

		// since it will return newest to oldest, we get page1[1] first
		page7, ttime := session.TestListSessionsRefresh(
			t,
			repo,
			context.Background(),
			time.Now().Add(-1*time.Second),
			session.WithLimit(1),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), page1[1].GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		page8, ttime := session.TestListSessionsRefresh(
			t,
			repo,
			context.Background(),
			time.Now().Add(-1*time.Second),
			session.WithLimit(1),
			session.WithStartPageAfterItem(page7[0]),
		)
		require.NoError(err)
		require.Len(page8, 1)
		require.Equal(page8[0].GetPublicId(), page1[0].GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func TestRepository_ListSessions_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()

	db.TestDeleteWhere(t, conn, func() any { i := session.AllocSession(); return &i }(), "1=1")

	const numPerScope = 10
	var p []perms.Permission
	for i := 0; i < numPerScope; i++ {
		composedOf := session.TestSessionParams(t, conn, wrapper, iamRepo)
		p = append(p, perms.Permission{
			ScopeId:  composedOf.ProjectId,
			Resource: resource.Session,
			Action:   action.List,
		})
		s := session.TestSession(t, conn, wrapper, composedOf)
		_ = session.TestState(t, conn, s.PublicId, session.StatusActive)
	}

	repo, err := session.NewRepository(ctx, rw, rw, kms, session.WithPermissions(&perms.UserPermissions{
		Permissions: p,
	}))
	require.NoError(t, err)
	got, ttime := session.TestListSessions(t, repo, context.Background())
	require.NoError(t, err)
	assert.Equal(t, len(p), len(got))
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestListDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	rw := db.New(conn)
	repo, err := session.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	composedOf := session.TestSessionParams(t, conn, wrapper, iamRepo)

	s := session.TestSession(t, conn, wrapper, composedOf)
	_ = session.TestState(t, conn, s.PublicId, session.StatusActive)

	// Expect no entries at the start
	deletedIds, ttime := session.TestListDeletedIds(t, repo, ctx, time.Now().AddDate(-1, 0, 0))
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a session
	_, err = repo.DeleteSession(ctx, s.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime = session.TestListDeletedIds(t, repo, ctx, time.Now().AddDate(-1, 0, 0))
	require.Equal(t, []string{s.GetPublicId()}, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime = session.TestListDeletedIds(t, repo, ctx, time.Now())
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestEstimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	rw := db.New(conn)
	repo, err := session.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	composedOf := session.TestSessionParams(t, conn, wrapper, iamRepo)

	// Check total entries at start, expect 0
	numItems := session.TestEstimatedCount(t, repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create a session, expect 1 entries
	s := session.TestSession(t, conn, wrapper, composedOf)
	_ = session.TestState(t, conn, s.PublicId, session.StatusActive)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems = session.TestEstimatedCount(t, repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the target, expect 0 again
	_, err = repo.DeleteSession(ctx, s.GetPublicId())
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems = session.TestEstimatedCount(t, repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}
