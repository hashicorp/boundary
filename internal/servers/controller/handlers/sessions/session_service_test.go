package sessions_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestGetSession(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)
	sessRepo, err := session.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func() (*session.Repository, error) {
		return sessRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, p.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := target.TestTcpTarget(t, conn, p.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))

	sess := session.TestSession(t, conn, wrap, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     p.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	wireSess := &pb.Session{
		Id:             sess.GetPublicId(),
		ScopeId:        p.GetPublicId(),
		AuthTokenId:    at.GetPublicId(),
		Endpoint:       sess.Endpoint,
		UserId:         at.GetIamUserId(),
		TargetId:       sess.TargetId,
		HostSetId:      sess.HostSetId,
		HostId:         sess.HostId,
		Version:        sess.Version,
		Status:         session.StatusPending.String(),
		UpdatedTime:    sess.UpdateTime.GetTimestamp(),
		CreatedTime:    sess.CreateTime.GetTimestamp(),
		ExpirationTime: sess.ExpirationTime.GetTimestamp(),
		Scope:          &scopes.ScopeInfo{Id: p.GetPublicId(), Type: scope.Project.String()},
		States:         []*pb.SessionState{{Status: session.StatusPending.String(), StartTime: sess.CreateTime.GetTimestamp()}},
		Certificate:    sess.Certificate,
		Type:           target.TcpSubType.String(),
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
			scopeId: sess.ScopeId,
			req:     &pbs.GetSessionRequest{Id: sess.GetPublicId()},
			res:     &pbs.GetSessionResponse{Item: wireSess},
		},
		{
			name: "Get a non existant Session",
			req:  &pbs.GetSessionRequest{Id: session.SessionPrefix + "_DoesntExis"},
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
			req:  &pbs.GetSessionRequest{Id: session.SessionPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := sessions.NewService(sessRepoFn, iamRepoFn)
			require.NoError(err, "Couldn't create new session service.")

			got, gErr := s.GetSession(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetSession(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if tc.res != nil {
				assert.True(got.GetItem().GetExpirationTime().AsTime().Sub(tc.res.GetItem().GetExpirationTime().AsTime()) < 10*time.Millisecond)
				tc.res.GetItem().ExpirationTime = got.GetItem().GetExpirationTime()
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetSession(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)
	sessRepo, err := session.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func() (*session.Repository, error) {
		return sessRepo, nil
	}

	_, pNoSessions := iam.TestScopes(t, iamRepo)
	o, pWithSessions := iam.TestScopes(t, iamRepo)

	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, pWithSessions.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := target.TestTcpTarget(t, conn, pWithSessions.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))

	var wantSession []*pb.Session
	for i := 0; i < 10; i++ {
		sess := session.TestSession(t, conn, wrap, session.ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ScopeId:     pWithSessions.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		status, states := convertStates(sess.States)

		wantSession = append(wantSession, &pb.Session{
			Id:             sess.GetPublicId(),
			ScopeId:        pWithSessions.GetPublicId(),
			AuthTokenId:    at.GetPublicId(),
			UserId:         at.GetIamUserId(),
			TargetId:       sess.TargetId,
			Endpoint:       sess.Endpoint,
			HostSetId:      sess.HostSetId,
			HostId:         sess.HostId,
			Version:        sess.Version,
			UpdatedTime:    sess.UpdateTime.GetTimestamp(),
			CreatedTime:    sess.CreateTime.GetTimestamp(),
			ExpirationTime: sess.ExpirationTime.GetTimestamp(),
			Scope:          &scopes.ScopeInfo{Id: pWithSessions.GetPublicId(), Type: scope.Project.String()},
			Status:         status,
			States:         states,
			Certificate:    sess.Certificate,
			Type:           target.TcpSubType.String(),
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListSessionsRequest
		res  *pbs.ListSessionsResponse
		err  error
	}{
		{
			name: "List Many Sessions",
			req:  &pbs.ListSessionsRequest{ScopeId: pWithSessions.GetPublicId()},
			res:  &pbs.ListSessionsResponse{Items: wantSession},
		},
		{
			name: "List No Sessions",
			req:  &pbs.ListSessionsRequest{ScopeId: pNoSessions.GetPublicId()},
			res:  &pbs.ListSessionsResponse{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := sessions.NewService(sessRepoFn, iamRepoFn)
			require.NoError(t, err, "Couldn't create new session service.")

			got, gErr := s.ListSessions(auth.DisabledAuthTestContext(auth.WithScopeId(tc.req.GetScopeId())), tc.req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "ListSessions(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if tc.res != nil {
				for i, wantSess := range tc.res.GetItems() {
					assert.True(t, got.GetItems()[i].GetExpirationTime().AsTime().Sub(wantSess.GetExpirationTime().AsTime()) < 10*time.Millisecond)
					wantSess.ExpirationTime = got.GetItems()[i].GetExpirationTime()
				}
			}
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform()), "ListSessions(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
	sessRepo, err := session.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func() (*session.Repository, error) {
		return sessRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, p.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := target.TestTcpTarget(t, conn, p.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))

	sess := session.TestSession(t, conn, wrap, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     p.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	wireSess := &pb.Session{
		Id:             sess.GetPublicId(),
		ScopeId:        p.GetPublicId(),
		AuthTokenId:    at.GetPublicId(),
		UserId:         at.GetIamUserId(),
		TargetId:       sess.TargetId,
		HostSetId:      sess.HostSetId,
		HostId:         sess.HostId,
		Version:        sess.Version,
		Endpoint:       sess.Endpoint,
		CreatedTime:    sess.CreateTime.GetTimestamp(),
		ExpirationTime: sess.ExpirationTime.GetTimestamp(),
		Scope:          &scopes.ScopeInfo{Id: p.GetPublicId(), Type: scope.Project.String()},
		Status:         session.StatusCanceling.String(),
		Certificate:    sess.Certificate,
		Type:           target.TcpSubType.String(),
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
			scopeId: sess.ScopeId,
			req:     &pbs.CancelSessionRequest{Id: sess.GetPublicId()},
			res:     &pbs.CancelSessionResponse{Item: wireSess},
		},
		{
			name: "Cancel a non existing Session",
			req:  &pbs.CancelSessionRequest{Id: session.SessionPrefix + "_DoesntExis"},
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
			req:  &pbs.CancelSessionRequest{Id: session.SessionPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := sessions.NewService(sessRepoFn, iamRepoFn)
			require.NoError(err, "Couldn't create new session service.")

			tc.req.Version = version

			got, gErr := s.CancelSession(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetSession(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

			if tc.res == nil {
				require.Nil(got)
				return
			}
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
			assert.Empty(cmp.Diff(got.GetItem().GetStates(), wantState, protocmp.Transform()), "GetSession(%q) states")
			got.GetItem().States = nil
			got.GetItem().UpdatedTime = nil

			if tc.res != nil {
				assert.True(got.GetItem().GetExpirationTime().AsTime().Sub(tc.res.GetItem().GetExpirationTime().AsTime()) < 10*time.Millisecond)
				tc.res.GetItem().ExpirationTime = got.GetItem().GetExpirationTime()
			}

			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetSession(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)

			if tc.req != nil {
				require.NotNil(got)
				version = got.GetItem().GetVersion()
			}
		})
	}
}
