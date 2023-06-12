// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sessions_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
)

var testAuthorizedActions = []string{"read:self", "cancel:self"}

func TestGetSession(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)

	ctx := context.Background()
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func(opt ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opt...)
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	o, p := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, p.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(context.Background(), t, conn, p.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	sess := session.TestSession(t, conn, wrap, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   p.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	wireSess := &pb.Session{
		Id:                sess.GetPublicId(),
		ScopeId:           p.GetPublicId(),
		AuthTokenId:       at.GetPublicId(),
		Endpoint:          sess.Endpoint,
		UserId:            at.GetIamUserId(),
		TargetId:          sess.TargetId,
		HostSetId:         sess.HostSetId,
		HostId:            sess.HostId,
		Version:           sess.Version,
		Status:            session.StatusPending.String(),
		UpdatedTime:       sess.UpdateTime.GetTimestamp(),
		CreatedTime:       sess.CreateTime.GetTimestamp(),
		ExpirationTime:    sess.ExpirationTime.GetTimestamp(),
		Scope:             &scopes.ScopeInfo{Id: p.GetPublicId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
		States:            []*pb.SessionState{{Status: session.StatusPending.String(), StartTime: sess.CreateTime.GetTimestamp()}},
		Certificate:       sess.Certificate,
		Type:              tcp.Subtype.String(),
		AuthorizedActions: testAuthorizedActions,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetSessionRequest
		res     *pbs.GetSessionResponse
		err     error
	}{
		{
			name:    "Get a session",
			scopeId: sess.ProjectId,
			req:     &pbs.GetSessionRequest{Id: sess.GetPublicId()},
			res:     &pbs.GetSessionResponse{Item: wireSess},
		},
		{
			name: "Get a non existent Session",
			req:  &pbs.GetSessionRequest{Id: globals.SessionPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetSessionRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetSessionRequest{Id: globals.SessionPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := sessions.NewService(ctx, sessRepoFn, iamRepoFn)
			require.NoError(err, "Couldn't create new session service.")

			requestInfo := authpb.RequestInfo{
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    at.GetPublicId(),
				Token:       at.GetToken(),
			}
			requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
			ctx := auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

			got, gErr := s.GetSession(ctx, tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetSession(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if tc.res != nil {
				assert.True(got.GetItem().GetExpirationTime().AsTime().Sub(tc.res.GetItem().GetExpirationTime().AsTime()) < 10*time.Millisecond)
				tc.res.GetItem().ExpirationTime = got.GetItem().GetExpirationTime()
			}
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "GetSession(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)
		})
	}
}

func TestList_Self(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)

	ctx := context.Background()
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func(opt ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opt...)
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	o, pWithSessions := iam.TestScopes(t, iamRepo)

	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()

	otherPrivAuthToken := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	unprivAuthToken := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())

	// See https://github.com/hashicorp/boundary/pull/2448 -- these roles both
	// test functionality and serve as a regression test

	// Create a "privileged" role that gives admin on the scope
	privProjRole := iam.TestRole(t, conn, pWithSessions.GetPublicId())
	iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "id=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privProjRole.GetPublicId(), otherPrivAuthToken.GetIamUserId())

	// Create an "unprivileged" role that only grants self variants and add the
	// unprivileged user and other privileged users
	unPrivProjRole := iam.TestRole(t, conn, pWithSessions.GetPublicId())
	iam.TestRoleGrant(t, conn, unPrivProjRole.GetPublicId(), "id=*;type=session;actions=read:self,list,cancel:self")
	iam.TestUserRole(t, conn, unPrivProjRole.GetPublicId(), unprivAuthToken.GetIamUserId())
	iam.TestUserRole(t, conn, unPrivProjRole.GetPublicId(), otherPrivAuthToken.GetIamUserId())

	hc := static.TestCatalogs(t, conn, pWithSessions.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(context.Background(), t, conn, pWithSessions.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	// By default a user can read/cancel their own sessions.
	session.TestSession(t, conn, wrap, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   pWithSessions.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	s, err := sessions.NewService(ctx, sessRepoFn, iamRepoFn)
	require.NoError(t, err, "Couldn't create new session service.")

	cases := []struct {
		name      string
		requester *authtoken.AuthToken
		count     int
	}{
		{
			name:      "List Self Sessions",
			requester: at,
			count:     1,
		},
		{
			name:      "Can List Others Sessions when Authorized",
			requester: otherPrivAuthToken,
			count:     1,
		},
		{
			name:      "Can't List Others Sessions When Not Authorized",
			requester: unprivAuthToken,
			count:     0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup the auth request information
			req := httptest.NewRequest("GET", fmt.Sprintf("http://127.0.0.1/v1/sessions?scope_id=%s", pWithSessions.GetPublicId()), nil)
			requestInfo := authpb.RequestInfo{
				Path:        req.URL.Path,
				Method:      req.Method,
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    tc.requester.GetPublicId(),
				Token:       tc.requester.GetToken(),
			}

			ctx := auth.NewVerifierContext(context.Background(), iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
			got, err := s.ListSessions(ctx, &pbs.ListSessionsRequest{ScopeId: pWithSessions.GetPublicId()})
			require.NoError(t, err)
			assert.Equal(t, tc.count, len(got.GetItems()), got.GetItems())
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	ctx := context.Background()

	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)
	sessRepo, err := session.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func(opt ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opt...)
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	_, pNoSessions := iam.TestScopes(t, iamRepo)
	o, pWithSessions := iam.TestScopes(t, iamRepo)
	oOther, pWithOtherSessions := iam.TestScopes(t, iamRepo)

	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()

	atOther := authtoken.TestAuthToken(t, conn, kms, oOther.GetPublicId())
	uIdOther := atOther.GetIamUserId()

	hc := static.TestCatalogs(t, conn, pWithSessions.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, pWithSessions.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	hcOther := static.TestCatalogs(t, conn, pWithOtherSessions.GetPublicId(), 1)[0]
	hsOther := static.TestSets(t, conn, hcOther.GetPublicId(), 1)[0]
	hOther := static.TestHosts(t, conn, hcOther.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hsOther.GetPublicId(), []*static.Host{hOther})
	tarOther := tcp.TestTarget(ctx, t, conn, pWithOtherSessions.GetPublicId(), "test", target.WithHostSources([]string{hsOther.GetPublicId()}))

	var wantSession []*pb.Session
	var wantOtherSession []*pb.Session
	var wantAllSessions []*pb.Session
	var wantIncludeTerminatedSessions []*pb.Session
	for i := 0; i < 10; i++ {
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

		status, states := convertStates(sess.States)

		firstOrgSession := &pb.Session{
			Id:                sess.GetPublicId(),
			ScopeId:           pWithSessions.GetPublicId(),
			AuthTokenId:       at.GetPublicId(),
			UserId:            at.GetIamUserId(),
			TargetId:          sess.TargetId,
			Endpoint:          sess.Endpoint,
			HostSetId:         sess.HostSetId,
			HostId:            sess.HostId,
			Version:           sess.Version,
			UpdatedTime:       sess.UpdateTime.GetTimestamp(),
			CreatedTime:       sess.CreateTime.GetTimestamp(),
			ExpirationTime:    sess.ExpirationTime.GetTimestamp(),
			Scope:             &scopes.ScopeInfo{Id: pWithSessions.GetPublicId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
			Status:            status,
			States:            states,
			Certificate:       sess.Certificate,
			Type:              tcp.Subtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Connections:       []*pb.Connection{}, // connections should not be returned for list
		}
		wantSession = append(wantSession, firstOrgSession)
		wantAllSessions = append(wantAllSessions, firstOrgSession)

		wantIncludeTerminatedSessions = append(wantIncludeTerminatedSessions, wantSession[i])

		sess = session.TestSession(t, conn, wrap, session.ComposedOf{
			UserId:      uIdOther,
			HostId:      hOther.GetPublicId(),
			TargetId:    tarOther.GetPublicId(),
			HostSetId:   hsOther.GetPublicId(),
			AuthTokenId: atOther.GetPublicId(),
			ProjectId:   pWithOtherSessions.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		session.TestConnection(t, conn, sess.PublicId, "127.0.0.1", 22, "127.0.0.2", 23, "127.0.0.1")

		status, states = convertStates(sess.States)

		otherOrgSession := &pb.Session{
			Id:                sess.GetPublicId(),
			ScopeId:           pWithSessions.GetPublicId(),
			AuthTokenId:       at.GetPublicId(),
			UserId:            at.GetIamUserId(),
			TargetId:          sess.TargetId,
			Endpoint:          sess.Endpoint,
			HostSetId:         sess.HostSetId,
			HostId:            sess.HostId,
			Version:           sess.Version,
			UpdatedTime:       sess.UpdateTime.GetTimestamp(),
			CreatedTime:       sess.CreateTime.GetTimestamp(),
			ExpirationTime:    sess.ExpirationTime.GetTimestamp(),
			Scope:             &scopes.ScopeInfo{Id: pWithSessions.GetPublicId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
			Status:            status,
			States:            states,
			Certificate:       sess.Certificate,
			Type:              tcp.Subtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Connections:       []*pb.Connection{}, // connections should not be returned for list
		}
		wantOtherSession = append(wantOtherSession, otherOrgSession)

		wantAllSessions = append(wantAllSessions, otherOrgSession)
	}

	{
		sess := session.TestSession(t, conn, wrap, session.ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   pWithSessions.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		sess, err := sessRepo.CancelSession(ctx, sess.PublicId, sess.Version)
		require.NoError(t, err)
		terminated, err := sessRepo.TerminateCompletedSessions(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, terminated)

		sess, _, err = sessRepo.LookupSession(ctx, sess.PublicId)
		require.NoError(t, err)
		status, states := convertStates(sess.States)

		expected := &pb.Session{
			Id:                sess.GetPublicId(),
			ScopeId:           pWithSessions.GetPublicId(),
			AuthTokenId:       at.GetPublicId(),
			UserId:            at.GetIamUserId(),
			TargetId:          sess.TargetId,
			Endpoint:          sess.Endpoint,
			HostSetId:         sess.HostSetId,
			HostId:            sess.HostId,
			Version:           sess.Version,
			UpdatedTime:       sess.UpdateTime.GetTimestamp(),
			CreatedTime:       sess.CreateTime.GetTimestamp(),
			ExpirationTime:    sess.ExpirationTime.GetTimestamp(),
			Scope:             &scopes.ScopeInfo{Id: pWithSessions.GetPublicId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
			Status:            status,
			States:            states,
			Certificate:       sess.Certificate,
			TerminationReason: sess.TerminationReason,
			Type:              tcp.Subtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Connections:       []*pb.Connection{}, // connections should not be returned for list
		}

		wantIncludeTerminatedSessions = append(wantIncludeTerminatedSessions, expected)
	}

	cases := []struct {
		name          string
		req           *pbs.ListSessionsRequest
		res           *pbs.ListSessionsResponse
		otherRes      *pbs.ListSessionsResponse
		allSessionRes *pbs.ListSessionsResponse
		err           error
	}{
		{
			name:          "List Many Sessions",
			req:           &pbs.ListSessionsRequest{ScopeId: pWithSessions.GetPublicId()},
			res:           &pbs.ListSessionsResponse{Items: wantSession},
			otherRes:      &pbs.ListSessionsResponse{Items: []*pb.Session{}},
			allSessionRes: &pbs.ListSessionsResponse{Items: wantSession},
		},
		{
			name:          "List Many Include Terminated",
			req:           &pbs.ListSessionsRequest{ScopeId: pWithSessions.GetPublicId(), IncludeTerminated: true},
			res:           &pbs.ListSessionsResponse{Items: wantIncludeTerminatedSessions},
			otherRes:      &pbs.ListSessionsResponse{Items: []*pb.Session{}},
			allSessionRes: &pbs.ListSessionsResponse{Items: wantIncludeTerminatedSessions},
		},
		{
			name:          "List No Sessions",
			req:           &pbs.ListSessionsRequest{ScopeId: pNoSessions.GetPublicId()},
			res:           &pbs.ListSessionsResponse{},
			otherRes:      &pbs.ListSessionsResponse{Items: []*pb.Session{}},
			allSessionRes: &pbs.ListSessionsResponse{},
		},
		{
			name:          "List Sessions Recursively",
			req:           &pbs.ListSessionsRequest{ScopeId: scope.Global.String(), Recursive: true},
			res:           &pbs.ListSessionsResponse{Items: wantSession},
			otherRes:      &pbs.ListSessionsResponse{Items: wantOtherSession},
			allSessionRes: &pbs.ListSessionsResponse{Items: wantAllSessions},
		},
		{
			name:          "Filter To Single Sessions",
			req:           &pbs.ListSessionsRequest{ScopeId: pWithSessions.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantSession[4].Id)},
			res:           &pbs.ListSessionsResponse{Items: wantSession[4:5]},
			otherRes:      &pbs.ListSessionsResponse{Items: []*pb.Session{}},
			allSessionRes: &pbs.ListSessionsResponse{Items: wantSession[4:5]},
		},
		{
			name: "Filter To Many Sessions",
			req: &pbs.ListSessionsRequest{
				ScopeId: scope.Global.String(), Recursive: true,
				Filter: fmt.Sprintf(`"/item/scope/id" matches "^%s"`, pWithSessions.GetPublicId()[:8]),
			},
			res:           &pbs.ListSessionsResponse{Items: wantSession},
			otherRes:      &pbs.ListSessionsResponse{Items: []*pb.Session{}},
			allSessionRes: &pbs.ListSessionsResponse{Items: wantSession},
		},
		{
			name:          "Filter To Nothing",
			req:           &pbs.ListSessionsRequest{ScopeId: pWithSessions.GetPublicId(), Filter: `"/item/id" == ""`},
			res:           &pbs.ListSessionsResponse{},
			otherRes:      &pbs.ListSessionsResponse{Items: []*pb.Session{}},
			allSessionRes: &pbs.ListSessionsResponse{},
		},
		{
			name:     "Filter Bad Format",
			req:      &pbs.ListSessionsRequest{ScopeId: pWithSessions.GetPublicId(), Filter: `//badformat/`},
			err:      handlers.InvalidArgumentErrorf("bad format", nil),
			otherRes: &pbs.ListSessionsResponse{Items: []*pb.Session{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			s, err := sessions.NewService(ctx, sessRepoFn, iamRepoFn)
			require.NoError(err, "Couldn't create new session service.")

			// Test without anon user
			requestInfo := authpb.RequestInfo{
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    at.GetPublicId(),
				Token:       at.GetToken(),
			}
			requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
			ctx := auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
			got, gErr := s.ListSessions(ctx, tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListSessions(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if tc.res != nil {
				require.Equal(len(tc.res.GetItems()), len(got.GetItems()), "Didn't get expected number of sessions: %v", got.GetItems())
				for i, wantSess := range tc.res.GetItems() {
					assert.True(got.GetItems()[i].GetExpirationTime().AsTime().Sub(wantSess.GetExpirationTime().AsTime()) < 10*time.Millisecond)
					assert.Equal(0, len(wantSess.GetConnections())) // no connections on list
					wantSess.ExpirationTime = got.GetItems()[i].GetExpirationTime()
				}
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListSessions(%q) got response %q, wanted %q", tc.req, got, tc.res)

			// Test with other user
			otherRequestInfo := authpb.RequestInfo{
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    atOther.GetPublicId(),
				Token:       atOther.GetToken(),
			}
			otherRequestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
			otherCtx := auth.NewVerifierContext(otherRequestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &otherRequestInfo)
			got, gErr = s.ListSessions(otherCtx, tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.otherRes.Items))
			for i, wantSess := range tc.otherRes.GetItems() {
				assert.True(got.GetItems()[i].GetExpirationTime().AsTime().Sub(wantSess.GetExpirationTime().AsTime()) < 10*time.Millisecond)
				assert.Equal(0, len(wantSess.GetConnections())) // no connections on list
				wantSess.ExpirationTime = got.GetItems()[i].GetExpirationTime()
			}

			// Test with recovery user
			recoveryRequestInfo := authpb.RequestInfo{
				TokenFormat: uint32(auth.AuthTokenTypeRecoveryKms),
				PublicId:    at.GetPublicId(),
				Token:       at.GetToken(),
			}
			recoveryRequestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
			recoveryCtx := auth.NewVerifierContext(recoveryRequestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &recoveryRequestInfo)
			recoveryGot, gErr := s.ListSessions(recoveryCtx, tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListSessions(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if tc.allSessionRes != nil {
				require.Equal(len(tc.allSessionRes.GetItems()), len(recoveryGot.GetItems()), "Didn't get expected number of sessions: %v", recoveryGot.GetItems())
				for i, wantSess := range tc.allSessionRes.GetItems() {
					assert.True(recoveryGot.GetItems()[i].GetExpirationTime().AsTime().Sub(wantSess.GetExpirationTime().AsTime()) < 10*time.Millisecond)
					assert.Equal(0, len(wantSess.GetConnections())) // no connections on list
					wantSess.ExpirationTime = recoveryGot.GetItems()[i].GetExpirationTime()
				}
			}
		})
	}
}

func convertStates(in []*session.State) (string, []*pb.SessionState) {
	out := make([]*pb.SessionState, 0, len(in))
	for _, s := range in {
		sessState := &pb.SessionState{
			Status: s.Status.String(),
		}
		if s.StartTime != nil {
			sessState.StartTime = s.StartTime.GetTimestamp()
		}
		if s.EndTime != nil {
			sessState.EndTime = s.EndTime.GetTimestamp()
		}
		out = append(out, sessState)
	}
	return out[0].Status, out
}

func TestCancel(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)

	ctx := context.Background()
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func(opt ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opt...)
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	o, p := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, p.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(context.Background(), t, conn, p.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	sess := session.TestSession(t, conn, wrap, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   p.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	wireSess := &pb.Session{
		Id:                sess.GetPublicId(),
		ScopeId:           p.GetPublicId(),
		AuthTokenId:       at.GetPublicId(),
		UserId:            at.GetIamUserId(),
		TargetId:          sess.TargetId,
		HostSetId:         sess.HostSetId,
		HostId:            sess.HostId,
		Version:           sess.Version,
		Endpoint:          sess.Endpoint,
		CreatedTime:       sess.CreateTime.GetTimestamp(),
		ExpirationTime:    sess.ExpirationTime.GetTimestamp(),
		Scope:             &scopes.ScopeInfo{Id: p.GetPublicId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
		Status:            session.StatusCanceling.String(),
		Certificate:       sess.Certificate,
		Type:              tcp.Subtype.String(),
		AuthorizedActions: testAuthorizedActions,
	}

	version := wireSess.GetVersion()

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.CancelSessionRequest
		res     *pbs.CancelSessionResponse
		err     error
	}{
		{
			name:    "Cancel a session",
			scopeId: sess.ProjectId,
			req:     &pbs.CancelSessionRequest{Id: sess.GetPublicId()},
			res:     &pbs.CancelSessionResponse{Item: wireSess},
		},
		{
			name:    "Already canceled",
			scopeId: sess.ProjectId,
			req:     &pbs.CancelSessionRequest{Id: sess.GetPublicId()},
			res:     &pbs.CancelSessionResponse{Item: wireSess},
		},
		{
			name: "Cancel a non existing Session",
			req:  &pbs.CancelSessionRequest{Id: globals.SessionPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.CancelSessionRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.CancelSessionRequest{Id: globals.SessionPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := sessions.NewService(ctx, sessRepoFn, iamRepoFn)
			require.NoError(err, "Couldn't create new session service.")

			tc.req.Version = version

			requestInfo := authpb.RequestInfo{
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    at.GetPublicId(),
				Token:       at.GetToken(),
			}
			requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
			ctx := auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
			got, gErr := s.CancelSession(ctx, tc.req)

			if tc.err != nil {
				require.Error(gErr)
				// It's hard to mix and match api/error package errors right now
				// so use old/new behavior depending on the type. If validate
				// gets updated this can be standardized.
				if errors.Match(errors.T(errors.InvalidSessionState), gErr) {
					assert.True(errors.Match(errors.T(tc.err), gErr), "CancelSession(%+v) got error %#v, wanted %#v", tc.req, gErr, tc.err)
				} else {
					assert.True(errors.Is(gErr, tc.err), "CancelSession(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				}
			}

			if tc.res == nil {
				require.Nil(got)
				return
			}
			require.NotNil(got)
			tc.res.GetItem().Version = got.GetItem().Version

			// Compare the new canceling state and then remove it for the rest of the proto comparison
			assert.True(got.GetItem().GetUpdatedTime().AsTime().After(got.GetItem().GetCreatedTime().AsTime()))
			assert.Len(got.GetItem().GetStates(), 2)

			wantState := []*pb.SessionState{
				{
					Status:    session.StatusCanceling.String(),
					StartTime: got.GetItem().GetUpdatedTime(),
				},
				{
					Status:    session.StatusPending.String(),
					StartTime: got.GetItem().GetCreatedTime(),
					EndTime:   got.GetItem().GetUpdatedTime(),
				},
			}
			assert.Empty(cmp.Diff(got.GetItem().GetStates(), wantState, protocmp.Transform()), "CancelSession(%q) states")
			got.GetItem().States = nil
			got.GetItem().UpdatedTime = nil

			if tc.res != nil {
				assert.True(got.GetItem().GetExpirationTime().AsTime().Sub(tc.res.GetItem().GetExpirationTime().AsTime()) < 10*time.Millisecond)
				tc.res.GetItem().ExpirationTime = got.GetItem().GetExpirationTime()
			}

			assert.Equal(got.GetItem().HostId, tc.res.GetItem().HostId)
			assert.Equal(got.GetItem().HostSetId, tc.res.GetItem().HostSetId)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CancelSession(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)

			if tc.req != nil {
				require.NotNil(got)
				version = got.GetItem().GetVersion()
			}
		})
	}
}
