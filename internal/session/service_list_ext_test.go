// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)
	o, pWithSessions := iam.TestScopes(t, iamRepo)

	composedOf := session.TestSessionParams(t, conn, wrap, iamRepo)

	listPerms := &perms.UserPermissions{
		UserId: composedOf.UserId,
		Permissions: []perms.Permission{
			{
				ScopeId:  pWithSessions.PublicId,
				Resource: resource.Session,
				Action:   action.List,
			},
		},
	}

	rw := db.New(conn)
	repo, err := session.NewRepository(ctx, rw, rw, kms, session.WithPermissions(listPerms))
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, pWithSessions.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, pWithSessions.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	var sessions []*session.Session
	for i := 0; i < 5; i++ {
		sess := session.TestSession(t, conn, wrap, session.ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   pWithSessions.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		session.TestConnection(t, conn, sess.PublicId, "127.0.0.1", 22, "127.0.0.2", 23, "127.0.0.1")

		sessions = append(sessions, sess)
	}

	// Run analyze to update host estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, nil, 1, filterFunc, repo, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, []byte("some hash"), 0, filterFunc, repo, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, []byte("some hash"), -1, filterFunc, repo, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := session.List(ctx, []byte("some hash"), 1, nil, repo, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, []byte("some hash"), 1, filterFunc, nil, false)
			require.ErrorContains(t, err, "missing repo")
		})
	})

	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = session.ListRefresh(ctx, nil, 1, filterFunc, tok, repo, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = session.ListRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = session.ListRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = session.ListRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err = session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, false)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, false)
			require.ErrorContains(t, err, "missing repo")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
			return true, nil
		}
		resp, err := session.List(ctx, []byte("some hash"), 1, filterFunc, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp.Items[0],
				sessions[0],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp2, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp2.Items[0],
				sessions[1],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp3, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp3.Items[0],
				sessions[2],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp4, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp4.Items[0],
				sessions[3],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp5, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp5.Items[0],
				sessions[4],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp6, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
			return s.GetPublicId() == sessions[len(sessions)-1].GetPublicId(), nil
		}
		resp, err := session.List(ctx, []byte("some hash"), 1, filterFunc, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp.Items[0],
				sessions[4],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp2, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		// Note: this might be surprising, but there isn't any way for the refresh
		// call to know that the last call got a different number.
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Empty(t, resp2.Items)
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
			return true, nil
		}
		deletedSessionId := sessions[0].GetPublicId()
		_, err := repo.DeleteSession(ctx, deletedSessionId)
		require.NoError(t, err)
		sessions = sessions[1:]

		// Run analyze to update host estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := session.List(ctx, []byte("some hash"), 1, filterFunc, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp.Items[0],
				sessions[0],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp2, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp2.Items[0],
				sessions[1],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		deletedSessionId = sessions[0].GetPublicId()
		_, err = repo.DeleteSession(ctx, deletedSessionId)
		require.NoError(t, err)
		sessions = sessions[1:]

		// Run analyze to update host estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedSessionId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp3.Items[0],
				sessions[1],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp4, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp4.Items[0],
				sessions[2],
				cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
				cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId"),
			),
		)

		resp5, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 3)
		require.Empty(t, resp5.Items)
	})
}
