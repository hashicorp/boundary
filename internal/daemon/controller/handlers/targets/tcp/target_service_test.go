package tcp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentiallibraries"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	credlibpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	credpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

var testAuthorizedActions = []string{
	"no-op",
	"read",
	"update",
	"delete",
	"add-host-sets",
	"set-host-sets",
	"remove-host-sets",
	"add-host-sources",
	"set-host-sources",
	"remove-host-sources",
	"add-credential-sources",
	"set-credential-sources",
	"remove-credential-sources",
	"authorize-session",
}

func testService(t *testing.T, ctx context.Context, conn *db.DB, kms *kms.Kms, wrapper wrapping.Wrapper) (targets.Service, error) {
	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	staticHostRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	vaultCredRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}
	staticCredRepoFn := func() (*credstatic.Repository, error) {
		return credstatic.NewRepository(context.Background(), rw, rw, kms)
	}
	return targets.NewService(ctx, kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, pluginHostRepoFn, staticHostRepoFn, vaultCredRepoFn, staticCredRepoFn)
}

func TestGet(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	o, proj := iam.TestScopes(t, iamRepo)

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	ctx := context.Background()
	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test", target.WithHostSources([]string{hs[0].GetPublicId(), hs[1].GetPublicId()}))

	pTar := &pb.Target{
		Id:                     tar.GetPublicId(),
		ScopeId:                proj.GetPublicId(),
		Name:                   wrapperspb.String("test"),
		CreatedTime:            tar.GetCreateTime().GetTimestamp(),
		UpdatedTime:            tar.GetUpdateTime().GetTimestamp(),
		Scope:                  &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
		Type:                   tcp.Subtype.String(),
		HostSetIds:             []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		HostSourceIds:          []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		Attrs:                  &pb.Target_TcpTargetAttributes{},
		SessionMaxSeconds:      wrapperspb.UInt32(28800),
		SessionConnectionLimit: wrapperspb.Int32(-1),
		AuthorizedActions:      testAuthorizedActions,
	}
	for _, ihs := range hs {
		pTar.HostSets = append(pTar.HostSets, &pb.HostSet{Id: ihs.GetPublicId(), HostCatalogId: ihs.GetCatalogId()})
		pTar.HostSources = append(pTar.HostSources, &pb.HostSource{Id: ihs.GetPublicId(), HostCatalogId: ihs.GetCatalogId()})
	}

	cases := []struct {
		name string
		req  *pbs.GetTargetRequest
		res  *pbs.GetTargetResponse
		err  error
	}{
		{
			name: "Get an Existing Target",
			req:  &pbs.GetTargetRequest{Id: tar.GetPublicId()},
			res:  &pbs.GetTargetResponse{Item: pTar},
		},
		{
			name: "Get a non existing Target",
			req:  &pbs.GetTargetRequest{Id: tcp.TargetPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetTargetRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetTargetRequest{Id: tcp.TargetPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := testService(t, context.Background(), conn, kms, wrapper)
			require.NoError(err, "Couldn't create a new host set service.")

			got, gErr := s.GetTarget(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetTarget(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetTarget(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, projNoTar := iam.TestScopes(t, iamRepo)
	org, proj := iam.TestScopes(t, iamRepo)
	otherOrg, otherProj := iam.TestScopes(t, iamRepo)
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	otherHc := static.TestCatalogs(t, conn, otherProj.GetPublicId(), 1)[0]
	hss := static.TestSets(t, conn, hc.GetPublicId(), 2)
	otherHss := static.TestSets(t, conn, otherHc.GetPublicId(), 2)
	ctx := context.Background()

	var wantTars []*pb.Target
	var totalTars []*pb.Target
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("tar%d", i)
		tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), name, target.WithHostSources([]string{hss[0].GetPublicId(), hss[1].GetPublicId()}))
		wantTars = append(wantTars, &pb.Target{
			Id:                     tar.GetPublicId(),
			ScopeId:                proj.GetPublicId(),
			Name:                   wrapperspb.String(name),
			Scope:                  &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
			CreatedTime:            tar.GetCreateTime().GetTimestamp(),
			UpdatedTime:            tar.GetUpdateTime().GetTimestamp(),
			Version:                tar.GetVersion(),
			Type:                   tcp.Subtype.String(),
			Attrs:                  &pb.Target_TcpTargetAttributes{},
			SessionMaxSeconds:      wrapperspb.UInt32(28800),
			SessionConnectionLimit: wrapperspb.Int32(-1),
			AuthorizedActions:      testAuthorizedActions,
		})
		totalTars = append(totalTars, wantTars[i])
		tar = tcp.TestTarget(ctx, t, conn, otherProj.GetPublicId(), name, target.WithHostSources([]string{otherHss[0].GetPublicId(), otherHss[1].GetPublicId()}))
		totalTars = append(totalTars, &pb.Target{
			Id:                     tar.GetPublicId(),
			ScopeId:                otherProj.GetPublicId(),
			Name:                   wrapperspb.String(name),
			Scope:                  &scopes.ScopeInfo{Id: otherProj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: otherOrg.GetPublicId()},
			CreatedTime:            tar.GetCreateTime().GetTimestamp(),
			UpdatedTime:            tar.GetUpdateTime().GetTimestamp(),
			Version:                tar.GetVersion(),
			Type:                   tcp.Subtype.String(),
			Attrs:                  &pb.Target_TcpTargetAttributes{},
			SessionMaxSeconds:      wrapperspb.UInt32(28800),
			SessionConnectionLimit: wrapperspb.Int32(-1),
			AuthorizedActions:      testAuthorizedActions,
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListTargetsRequest
		res  *pbs.ListTargetsResponse
		err  error
	}{
		{
			name: "List Many Targets",
			req:  &pbs.ListTargetsRequest{ScopeId: proj.GetPublicId()},
			res:  &pbs.ListTargetsResponse{Items: wantTars},
		},
		{
			name: "List No Targets",
			req:  &pbs.ListTargetsRequest{ScopeId: projNoTar.GetPublicId()},
			res:  &pbs.ListTargetsResponse{},
		},
		{
			name: "List Targets Recursively",
			req:  &pbs.ListTargetsRequest{ScopeId: scope.Global.String(), Recursive: true},
			res:  &pbs.ListTargetsResponse{Items: totalTars},
		},
		{
			name: "Filter To Many Targets",
			req:  &pbs.ListTargetsRequest{ScopeId: scope.Global.String(), Recursive: true, Filter: fmt.Sprintf(`"/item/scope/id"==%q`, proj.GetPublicId())},
			res:  &pbs.ListTargetsResponse{Items: wantTars},
		},
		{
			name: "Filter To No Targets",
			req:  &pbs.ListTargetsRequest{ScopeId: proj.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:  &pbs.ListTargetsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListTargetsRequest{ScopeId: proj.GetPublicId(), Filter: `"/badformat/"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := testService(t, context.Background(), conn, kms, wrapper)
			require.NoError(err, "Couldn't create new host set service.")

			// Test with non-anon user
			got, gErr := s.ListTargets(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListTargets(%q) got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Equal(len(tc.res.Items), len(got.Items))
			wantById := make(map[string]*pb.Target, len(tc.res.Items))
			for _, t := range tc.res.Items {
				wantById[t.Id] = t
			}
			for _, t := range got.Items {
				want, ok := wantById[t.Id]
				assert.True(ok, "Got unexpected target with id: %s", t.Id)
				assert.Empty(cmp.Diff(t, want, protocmp.Transform()), "got %v, wanted %v", t, want)
			}

			// Test with anon user
			got, gErr = s.ListTargets(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Empty(item.Version)
				require.Nil(item.CreatedTime)
				require.Nil(item.UpdatedTime)
				require.Nil(item.SessionMaxSeconds)
				require.Nil(item.SessionConnectionLimit)
				require.Empty(item.WorkerFilter)
				require.Nil(item.Attrs)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	ctx := context.Background()
	_, proj := iam.TestScopes(t, iamRepo)
	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test")

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Couldn't create a new target service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteTargetRequest
		res     *pbs.DeleteTargetResponse
		err     error
	}{
		{
			name:    "Delete an Existing Target",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteTargetRequest{
				Id: tar.GetPublicId(),
			},
		},
		{
			name:    "Delete Not Existing Target",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteTargetRequest{
				Id: tcp.TargetPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad target id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteTargetRequest{
				Id: tcp.TargetPrefix + "_bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteTarget(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteTarget(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "DeleteTarget(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	ctx := context.Background()
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test")

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(err, "Couldn't create a new target service.")
	req := &pbs.DeleteTargetRequest{
		Id: tar.GetPublicId(),
	}
	ctx = auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())
	_, gErr := s.DeleteTarget(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteTarget(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	cases := []struct {
		name string
		req  *pbs.CreateTargetRequest
		res  *pbs.CreateTargetResponse
		err  error
	}{
		{
			name: "Create a valid target",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				ScopeId:     proj.GetPublicId(),
				Name:        wrapperspb.String("name"),
				Description: wrapperspb.String("desc"),
				Type:        tcp.Subtype.String(),
				Attrs: &pb.Target_TcpTargetAttributes{
					TcpTargetAttributes: &pb.TcpTargetAttributes{
						DefaultPort: wrapperspb.UInt32(2),
					},
				},
				WorkerFilter: wrapperspb.String(`type == "bar"`),
			}},
			res: &pbs.CreateTargetResponse{
				Uri: fmt.Sprintf("targets/%s_", tcp.TargetPrefix),
				Item: &pb.Target{
					ScopeId:     proj.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					Type:        tcp.Subtype.String(),
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort: wrapperspb.UInt32(2),
						},
					},
					SessionMaxSeconds:      wrapperspb.UInt32(28800),
					SessionConnectionLimit: wrapperspb.Int32(-1),
					AuthorizedActions:      testAuthorizedActions,
					WorkerFilter:           wrapperspb.String(`type == "bar"`),
				},
			},
		},
		{
			name: "Create a target with no port",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				ScopeId:      proj.GetPublicId(),
				Name:         wrapperspb.String("name"),
				Description:  wrapperspb.String("desc"),
				Type:         tcp.Subtype.String(),
				WorkerFilter: wrapperspb.String(`type == "bar"`),
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with default port 0",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Name:        wrapperspb.String("name"),
				Description: wrapperspb.String("desc"),
				Type:        tcp.Subtype.String(),
				Attrs: &pb.Target_TcpTargetAttributes{
					TcpTargetAttributes: &pb.TcpTargetAttributes{
						DefaultPort: wrapperspb.UInt32(2),
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Name:        wrapperspb.String("name"),
				Description: wrapperspb.String("desc"),
				Type:        "ThisIsMadeUp",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with no type",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Name:        wrapperspb.String("name"),
				Description: wrapperspb.String("desc"),
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Id: "not allowed to be set",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				CreatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				UpdatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid worker filter expression",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				WorkerFilter: wrapperspb.String("bad expression"),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := testService(t, context.Background(), conn, kms, wrapper)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateTarget(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateTarget(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			} else {
				assert.Nil(gErr, "Unexpected err: %v", gErr)
			}

			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), tcp.TargetPrefix), got.GetItem().GetId())

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateTarget(%q)\n got response %q\n, wanted %q\n", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new target repo.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)
	hsIds := []string{hs[0].GetPublicId(), hs[1].GetPublicId()}
	hostSets := []*pb.HostSet{
		{Id: hs[0].GetPublicId(), HostCatalogId: hs[0].GetCatalogId()},
		{Id: hs[1].GetPublicId(), HostCatalogId: hs[1].GetCatalogId()},
	}
	hostSourceIds := []string{hs[0].GetPublicId(), hs[1].GetPublicId()}
	hostSources := []*pb.HostSource{
		{Id: hs[0].GetPublicId(), HostCatalogId: hs[0].GetCatalogId()},
		{Id: hs[1].GetPublicId(), HostCatalogId: hs[1].GetCatalogId()},
	}

	ctx := context.Background()
	ttar, err := target.New(ctx, tcp.Subtype, proj.GetPublicId(),
		target.WithName("default"),
		target.WithDescription("default"),
		target.WithSessionMaxSeconds(1),
		target.WithSessionConnectionLimit(1),
		target.WithDefaultPort(2))
	require.NoError(t, err)
	tar, _, _, err := repo.CreateTarget(context.Background(), ttar)
	require.NoError(t, err)
	tar, _, _, err = repo.AddTargetHostSources(context.Background(), tar.GetPublicId(), tar.GetVersion(), []string{hs[0].GetPublicId(), hs[1].GetPublicId()})
	require.NoError(t, err)

	resetTarget := func() {
		itar, _, _, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
		require.NoError(t, err)

		tar, _, _, _, err = repo.UpdateTarget(context.Background(), tar, itar.GetVersion(),
			[]string{"Name", "Description", "SessionMaxSeconds", "SessionConnectionLimit", "DefaultPort"})
		require.NoError(t, err, "Failed to reset target.")
	}

	hCreated := tar.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateTargetRequest{
		Id: tar.GetPublicId(),
	}

	tested, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Failed to create a new host set service.")

	cases := []struct {
		name string
		req  *pbs.UpdateTargetRequest
		res  *pbs.UpdateTargetResponse
		err  error
	}{
		{
			name: "Update an Existing Target",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "session_max_seconds", "session_connection_limit", "type"},
				},
				Item: &pb.Target{
					Name:                   wrapperspb.String("name"),
					Description:            wrapperspb.String("desc"),
					SessionMaxSeconds:      wrapperspb.UInt32(3600),
					SessionConnectionLimit: wrapperspb.Int32(5),
					Type:                   tcp.Subtype.String(),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					Type:        tcp.Subtype.String(),
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort: wrapperspb.UInt32(2),
						},
					},
					CreatedTime:            tar.GetCreateTime().GetTimestamp(),
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					HostSourceIds:          hostSourceIds,
					HostSources:            hostSources,
					SessionMaxSeconds:      wrapperspb.UInt32(3600),
					SessionConnectionLimit: wrapperspb.Int32(5),
					AuthorizedActions:      testAuthorizedActions,
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.Target{
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					Type:        tcp.Subtype.String(),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        tcp.Subtype.String(),
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort: wrapperspb.UInt32(2),
						},
					},
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					HostSourceIds:          hostSourceIds,
					HostSources:            hostSources,
					SessionMaxSeconds:      wrapperspb.UInt32(tar.GetSessionMaxSeconds()),
					SessionConnectionLimit: wrapperspb.Int32(tar.GetSessionConnectionLimit()),
					AuthorizedActions:      testAuthorizedActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateTargetRequest{
				Item: &pb.Target{
					Name:        wrapperspb.String("updated name"),
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Target{
					Name:        wrapperspb.String("updated name"),
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update port to 0",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"attributes.default_port"}},
				Item: &pb.Target{
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort: wrapperspb.UInt32(0),
						},
					},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Clear port",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"attributes.default_port"}},
				Item:       &pb.Target{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Target{
					Name:        wrapperspb.String("updated name"),
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Target{
					Description: wrapperspb.String("ignored"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Target{
					Name: wrapperspb.String("ignored"),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("default"),
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        tcp.Subtype.String(),
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort: wrapperspb.UInt32(2),
						},
					},
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					HostSourceIds:          hostSourceIds,
					HostSources:            hostSources,
					SessionMaxSeconds:      wrapperspb.UInt32(tar.GetSessionMaxSeconds()),
					SessionConnectionLimit: wrapperspb.Int32(tar.GetSessionConnectionLimit()),
					AuthorizedActions:      testAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Target{
					Name:        wrapperspb.String("updated"),
					Description: wrapperspb.String("ignored"),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("updated"),
					Description: wrapperspb.String("default"),
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        tcp.Subtype.String(),
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort: wrapperspb.UInt32(2),
						},
					},
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					HostSourceIds:          hostSourceIds,
					HostSources:            hostSources,
					SessionMaxSeconds:      wrapperspb.UInt32(tar.GetSessionMaxSeconds()),
					SessionConnectionLimit: wrapperspb.Int32(tar.GetSessionConnectionLimit()),
					AuthorizedActions:      testAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Target{
					Name:        wrapperspb.String("ignored"),
					Description: wrapperspb.String("notignored"),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("default"),
					Description: wrapperspb.String("notignored"),
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort: wrapperspb.UInt32(2),
						},
					},
					Type:                   tcp.Subtype.String(),
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					HostSourceIds:          hostSourceIds,
					HostSources:            hostSources,
					SessionMaxSeconds:      wrapperspb.UInt32(tar.GetSessionMaxSeconds()),
					SessionConnectionLimit: wrapperspb.Int32(tar.GetSessionConnectionLimit()),
					AuthorizedActions:      testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Target",
			req: &pbs.UpdateTargetRequest{
				Id: tcp.TargetPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Target{
					Name:        wrapperspb.String("new"),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Description: wrapperspb.String("desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateTargetRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Target{
					Id:          "p_somethinge",
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("new"),
					Description: wrapperspb.String("new desc"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Target{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Target{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetTarget()
			assert, require := assert.New(t), require.New(t)
			tc.req.Item.Version = tar.GetVersion()

			req := proto.Clone(toMerge).(*pbs.UpdateTargetRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateTarget(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateTarget(%+v) got error %v, wanted %v", req, gErr, tc.err)
				return
			}
			require.NoError(gErr)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHost response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a set updated after it was created
				// TODO: This is currently failing.
				assert.True(gotUpdateTime.After(hCreated), "Updated target should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, hCreated)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = tc.req.Item.Version + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateTarget(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate_BadVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new target repo.")

	ctx := context.Background()
	ttar, err := target.New(ctx, tcp.Subtype, proj.GetPublicId(), target.WithName("default"), target.WithDescription("default"))
	tar := ttar.(*tcp.Target)
	tar.DefaultPort = 2
	require.NoError(t, err)
	gtar, _, _, err := repo.CreateTarget(context.Background(), tar)
	require.NoError(t, err)

	tested, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Failed to create a new host set service.")

	upTar, err := tested.UpdateTarget(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), &pbs.UpdateTargetRequest{
		Id: gtar.GetPublicId(),
		Item: &pb.Target{
			Description: wrapperspb.String("updated"),
			Version:     72,
		},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	assert.Nil(t, upTar)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, handlers.NotFoundError()), "Got %v, wanted not found error.", err)
}

func TestAddTargetHostSets(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	plg := host.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginHs := plugin.TestSet(t, conn, kms, sche, pluginHc, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	})
	ctx := context.Background()

	addCases := []struct {
		name           string
		tar            target.Target
		addHostSets    []string
		resultHostSets []string
	}{
		{
			name:           "Add set on empty target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty"),
			addHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Add set on populated target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			addHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
		{
			name:           "Add duplicated sets on populated target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			addHostSets:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHostSets: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
		{
			name:           "Add plugin set on empty target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "plugin empty"),
			addHostSets:    []string{pluginHs.GetPublicId()},
			resultHostSets: []string{pluginHs.GetPublicId()},
		},
		{
			name:           "Add plugin set on populated target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "plugin populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			addHostSets:    []string{pluginHs.GetPublicId()},
			resultHostSets: []string{hs[0].GetPublicId(), pluginHs.GetPublicId()},
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.AddTargetHostSetsRequest{
				Id:         tc.tar.GetPublicId(),
				Version:    tc.tar.GetVersion(),
				HostSetIds: tc.addHostSets,
			}

			got, err := s.AddTargetHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHostSets, got.GetItem().GetHostSetIds())
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test")

	failCases := []struct {
		name string
		req  *pbs.AddTargetHostSetsRequest
		err  error
	}{
		{
			name: "Bad Set Id",
			req: &pbs.AddTargetHostSetsRequest{
				Id:         "bad id",
				Version:    tar.GetVersion(),
				HostSetIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.AddTargetHostSetsRequest{
				Id:         tar.GetPublicId(),
				Version:    tar.GetVersion() + 2,
				HostSetIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Empty host set list",
			req: &pbs.AddTargetHostSetsRequest{
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect host set ids",
			req: &pbs.AddTargetHostSetsRequest{
				Id:         tar.GetPublicId(),
				Version:    tar.GetVersion(),
				HostSetIds: []string{"incorrect"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddTargetHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddTargetHostSets(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetTargetHostSets(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	plg := host.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginHs := plugin.TestSet(t, conn, kms, sche, pluginHc, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	})

	ctx := context.Background()
	setCases := []struct {
		name           string
		tar            target.Target
		setHostSets    []string
		resultHostSets []string
	}{
		{
			name:           "Set on empty target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty"),
			setHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Set on populated target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Set duplicate host set on populated target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicate", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSets:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Set empty on populated target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "another populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSets:    []string{},
			resultHostSets: nil,
		},
		{
			name:           "Set plugin set on empty target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "plugin empty"),
			setHostSets:    []string{pluginHs.GetPublicId()},
			resultHostSets: []string{pluginHs.GetPublicId()},
		},
		{
			name:           "Set plugin set on populated target",
			tar:            tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "plugin populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSets:    []string{pluginHs.GetPublicId()},
			resultHostSets: []string{pluginHs.GetPublicId()},
		},
	}
	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.SetTargetHostSetsRequest{
				Id:         tc.tar.GetPublicId(),
				Version:    tc.tar.GetVersion(),
				HostSetIds: tc.setHostSets,
			}

			got, err := s.SetTargetHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.NoError(t, err, "Got error: %v", s)
			assert.ElementsMatch(t, tc.resultHostSets, got.GetItem().GetHostSetIds())
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test name")

	failCases := []struct {
		name string
		req  *pbs.SetTargetHostSetsRequest
		err  error
	}{
		{
			name: "Bad target Id",
			req: &pbs.SetTargetHostSetsRequest{
				Id:         "bad id",
				Version:    tar.GetVersion(),
				HostSetIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.SetTargetHostSetsRequest{
				Id:         tar.GetPublicId(),
				Version:    tar.GetVersion() + 3,
				HostSetIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad host set id",
			req: &pbs.SetTargetHostSetsRequest{
				Id:         tar.GetPublicId(),
				Version:    tar.GetVersion(),
				HostSetIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetTargetHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetTargetHostSets(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveTargetHostSets(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	plg := host.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginHs := plugin.TestSet(t, conn, kms, sche, pluginHc, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	})

	ctx := context.Background()
	removeCases := []struct {
		name        string
		tar         target.Target
		removeHosts []string
		resultHosts []string
		wantErr     bool
	}{
		{
			name:        "Remove from empty",
			tar:         tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty"),
			removeHosts: []string{hs[1].GetPublicId()},
			wantErr:     true,
		},
		{
			name:        "Remove 1 of 2 sets",
			tar:         tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove partial", target.WithHostSources([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHosts: []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
		{
			name:        "Remove 1 duplicate set of 2 sets",
			tar:         tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove duplicate", target.WithHostSources([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHosts: []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
		{
			name:        "Remove all hosts from set",
			tar:         tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove all", target.WithHostSources([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHosts: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{},
		},
		{
			name:        "Remove 1 plugin of 2 sets",
			tar:         tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove plugin partial", target.WithHostSources([]string{hs[0].GetPublicId(), pluginHs.GetPublicId()})),
			removeHosts: []string{pluginHs.GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
	}

	for _, tc := range removeCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.RemoveTargetHostSetsRequest{
				Id:         tc.tar.GetPublicId(),
				Version:    tc.tar.GetVersion(),
				HostSetIds: tc.removeHosts,
			}

			got, err := s.RemoveTargetHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHosts, got.GetItem().GetHostSetIds())
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "testing")

	failCases := []struct {
		name string
		req  *pbs.RemoveTargetHostSetsRequest
		err  error
	}{
		{
			name: "Bad version",
			req: &pbs.RemoveTargetHostSetsRequest{
				Id:         tar.GetPublicId(),
				Version:    tar.GetVersion() + 3,
				HostSetIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad target Id",
			req: &pbs.RemoveTargetHostSetsRequest{
				Id:         "bad id",
				Version:    tar.GetVersion(),
				HostSetIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "empty sets",
			req: &pbs.RemoveTargetHostSetsRequest{
				Id:         tar.GetPublicId(),
				Version:    tar.GetVersion(),
				HostSetIds: []string{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid set ids",
			req: &pbs.RemoveTargetHostSetsRequest{
				Id:         tar.GetPublicId(),
				Version:    tar.GetVersion(),
				HostSetIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveTargetHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveTargetHostSets(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestAddTargetHostSources(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	plg := host.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginHs := plugin.TestSet(t, conn, kms, sche, pluginHc, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	})

	ctx := context.Background()
	addCases := []struct {
		name              string
		tar               target.Target
		addHostSources    []string
		resultHostSources []string
	}{
		{
			name:              "Add set on empty target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty"),
			addHostSources:    []string{hs[1].GetPublicId()},
			resultHostSources: []string{hs[1].GetPublicId()},
		},
		{
			name:              "Add set on populated target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			addHostSources:    []string{hs[1].GetPublicId()},
			resultHostSources: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
		{
			name:              "Add duplicated sets on populated target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			addHostSources:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHostSources: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
		{
			name:              "Add plugin set on empty target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "plugin empty"),
			addHostSources:    []string{pluginHs.GetPublicId()},
			resultHostSources: []string{pluginHs.GetPublicId()},
		},
		{
			name:              "Add plugin set on populated target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "plugin populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			addHostSources:    []string{pluginHs.GetPublicId()},
			resultHostSources: []string{hs[0].GetPublicId(), pluginHs.GetPublicId()},
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.AddTargetHostSourcesRequest{
				Id:            tc.tar.GetPublicId(),
				Version:       tc.tar.GetVersion(),
				HostSourceIds: tc.addHostSources,
			}

			got, err := s.AddTargetHostSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHostSources, got.GetItem().GetHostSourceIds())
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test")

	failCases := []struct {
		name string
		req  *pbs.AddTargetHostSourcesRequest
		err  error
	}{
		{
			name: "Bad Set Id",
			req: &pbs.AddTargetHostSourcesRequest{
				Id:            "bad id",
				Version:       tar.GetVersion(),
				HostSourceIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.AddTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion() + 2,
				HostSourceIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Empty host set list",
			req: &pbs.AddTargetHostSourcesRequest{
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect host set ids",
			req: &pbs.AddTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion(),
				HostSourceIds: []string{"incorrect"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddTargetHostSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddTargetHostSources(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetTargetHostSources(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	plg := host.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginHs := plugin.TestSet(t, conn, kms, sche, pluginHc, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	})

	ctx := context.Background()
	setCases := []struct {
		name              string
		tar               target.Target
		setHostSources    []string
		resultHostSources []string
	}{
		{
			name:              "Set on empty target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty"),
			setHostSources:    []string{hs[1].GetPublicId()},
			resultHostSources: []string{hs[1].GetPublicId()},
		},
		{
			name:              "Set on populated target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSources:    []string{hs[1].GetPublicId()},
			resultHostSources: []string{hs[1].GetPublicId()},
		},
		{
			name:              "Set plugin set on populated target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "plugin populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSources:    []string{pluginHs.GetPublicId()},
			resultHostSources: []string{pluginHs.GetPublicId()},
		},
		{
			name:              "Set duplicate host set on populated target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicate", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSources:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHostSources: []string{hs[1].GetPublicId()},
		},
		{
			name:              "Set empty on populated target",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "another populated", target.WithHostSources([]string{hs[0].GetPublicId()})),
			setHostSources:    []string{},
			resultHostSources: nil,
		},
	}
	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.SetTargetHostSourcesRequest{
				Id:            tc.tar.GetPublicId(),
				Version:       tc.tar.GetVersion(),
				HostSourceIds: tc.setHostSources,
			}

			got, err := s.SetTargetHostSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.NoError(t, err, "Got error: %v", s)
			assert.ElementsMatch(t, tc.resultHostSources, got.GetItem().GetHostSourceIds())
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test name")

	failCases := []struct {
		name string
		req  *pbs.SetTargetHostSourcesRequest
		err  error
	}{
		{
			name: "Bad target Id",
			req: &pbs.SetTargetHostSourcesRequest{
				Id:            "bad id",
				Version:       tar.GetVersion(),
				HostSourceIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.SetTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion() + 3,
				HostSourceIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad host set id",
			req: &pbs.SetTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion(),
				HostSourceIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetTargetHostSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetTargetHostSources(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveTargetHostSources(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	plg := host.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginHs := plugin.TestSet(t, conn, kms, sche, pluginHc, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	})

	ctx := context.Background()
	removeCases := []struct {
		name              string
		tar               target.Target
		removeHostSources []string
		resultHostSources []string
		wantErr           bool
	}{
		{
			name:              "Remove from empty",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty"),
			removeHostSources: []string{hs[1].GetPublicId()},
			wantErr:           true,
		},
		{
			name:              "Remove 1 of 2 sets",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove partial", target.WithHostSources([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHostSources: []string{hs[1].GetPublicId()},
			resultHostSources: []string{hs[0].GetPublicId()},
		},
		{
			name:              "Remove 1 plugin set of 2 sets",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove plugin partial", target.WithHostSources([]string{hs[0].GetPublicId(), pluginHs.GetPublicId()})),
			removeHostSources: []string{pluginHs.GetPublicId()},
			resultHostSources: []string{hs[0].GetPublicId()},
		},
		{
			name:              "Remove 1 duplicate set of 2 sets",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove duplicate", target.WithHostSources([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHostSources: []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHostSources: []string{hs[0].GetPublicId()},
		},
		{
			name:              "Remove all hosts from set",
			tar:               tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove all", target.WithHostSources([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHostSources: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
			resultHostSources: []string{},
		},
	}

	for _, tc := range removeCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.RemoveTargetHostSourcesRequest{
				Id:            tc.tar.GetPublicId(),
				Version:       tc.tar.GetVersion(),
				HostSourceIds: tc.removeHostSources,
			}

			got, err := s.RemoveTargetHostSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHostSources, got.GetItem().GetHostSourceIds())
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "testing")

	failCases := []struct {
		name string
		req  *pbs.RemoveTargetHostSourcesRequest
		err  error
	}{
		{
			name: "Bad version",
			req: &pbs.RemoveTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion() + 3,
				HostSourceIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad target Id",
			req: &pbs.RemoveTargetHostSourcesRequest{
				Id:            "bad id",
				Version:       tar.GetVersion(),
				HostSourceIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "empty sets",
			req: &pbs.RemoveTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion(),
				HostSourceIds: []string{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid set ids",
			req: &pbs.RemoveTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion(),
				HostSourceIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveTargetHostSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveTargetHostSets(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestAddTargetCredentialSources(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	storeVault := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	cls := vault.TestCredentialLibraries(t, conn, wrapper, storeVault.GetPublicId(), 2)

	storeStatic := credstatic.TestCredentialStore(t, conn, wrapper, proj.GetPublicId())
	creds := credstatic.TestUsernamePasswordCredentials(t, conn, wrapper, "user", "pass", storeStatic.GetPublicId(), proj.GetPublicId(), 2)

	ctx := context.Background()
	addCases := []struct {
		name            string
		tar             target.Target
		addSources      []string
		resultSourceIds []string
	}{
		{
			name:            "Add library on empty target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty for lib sources"),
			addSources:      []string{cls[1].GetPublicId()},
			resultSourceIds: []string{cls[1].GetPublicId()},
		},
		{
			name:            "Add static cred on empty target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty for static sources"),
			addSources:      []string{creds[1].GetPublicId()},
			resultSourceIds: []string{creds[1].GetPublicId()},
		},
		{
			name:            "Add library on library populated target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated for lib-lib sources", target.WithCredentialLibraries([]*target.CredentialLibrary{target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose)})),
			addSources:      []string{cls[1].GetPublicId()},
			resultSourceIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
		},
		{
			name:            "Add library on static cred populated target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated for lib-static sources", target.WithStaticCredentials([]*target.StaticCredential{target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose)})),
			addSources:      []string{cls[1].GetPublicId()},
			resultSourceIds: []string{creds[0].GetPublicId(), cls[1].GetPublicId()},
		},
		{
			name:            "Add static cred on library populated target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated for static-lib sources", target.WithCredentialLibraries([]*target.CredentialLibrary{target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose)})),
			addSources:      []string{creds[1].GetPublicId()},
			resultSourceIds: []string{cls[0].GetPublicId(), creds[1].GetPublicId()},
		},
		{
			name:            "Add static cred on static cred populated target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated for static-static sources", target.WithStaticCredentials([]*target.StaticCredential{target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose)})),
			addSources:      []string{creds[1].GetPublicId()},
			resultSourceIds: []string{creds[0].GetPublicId(), creds[1].GetPublicId()},
		},
		{
			name:            "Add duplicated sources on library populated target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicated for lib sources", target.WithCredentialLibraries([]*target.CredentialLibrary{target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose)})),
			addSources:      []string{cls[1].GetPublicId(), cls[1].GetPublicId(), creds[1].GetPublicId(), creds[1].GetPublicId()},
			resultSourceIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId(), creds[1].GetPublicId()},
		},
		{
			name:            "Add duplicated sources on static cred populated target",
			tar:             tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicated for static sources", target.WithStaticCredentials([]*target.StaticCredential{target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose)})),
			addSources:      []string{cls[1].GetPublicId(), cls[1].GetPublicId(), creds[1].GetPublicId(), creds[1].GetPublicId()},
			resultSourceIds: []string{creds[0].GetPublicId(), cls[1].GetPublicId(), creds[1].GetPublicId()},
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.AddTargetCredentialSourcesRequest{
				Id:                             tc.tar.GetPublicId(),
				Version:                        tc.tar.GetVersion(),
				ApplicationCredentialSourceIds: tc.addSources,
			}

			got, err := s.AddTargetCredentialSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultSourceIds, got.GetItem().GetApplicationCredentialSourceIds())
			assert.Equal(t, len(tc.resultSourceIds), len(got.GetItem().GetApplicationCredentialSources()))
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test")

	failCases := []struct {
		name string
		req  *pbs.AddTargetCredentialSourcesRequest
		err  error
	}{
		{
			name: "Bad target id",
			req: &pbs.AddTargetCredentialSourcesRequest{
				Id:      "bad id",
				Version: tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{
					cls[0].GetPublicId(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.AddTargetCredentialSourcesRequest{
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion() + 2,
				ApplicationCredentialSourceIds: []string{
					cls[0].GetPublicId(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Empty source list",
			req: &pbs.AddTargetCredentialSourcesRequest{
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect source id",
			req: &pbs.AddTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				Version:                        tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{"incorrect"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddTargetCredentialSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddTargetCredentialSources(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetTargetCredentialSources(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	storeVault := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	cls := vault.TestCredentialLibraries(t, conn, wrapper, storeVault.GetPublicId(), 2)

	storeStatic := credstatic.TestCredentialStore(t, conn, wrapper, proj.GetPublicId())
	creds := credstatic.TestUsernamePasswordCredentials(t, conn, wrapper, "user", "pass", storeStatic.GetPublicId(), proj.GetPublicId(), 2)

	ctx := context.Background()
	setCases := []struct {
		name                      string
		tar                       target.Target
		setCredentialSources      []string
		resultCredentialSourceIds []string
	}{
		{
			name:                      "Set library on empty target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty library"),
			setCredentialSources:      []string{cls[1].GetPublicId()},
			resultCredentialSourceIds: []string{cls[1].GetPublicId()},
		},
		{
			name:                      "Set static on empty target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty static"),
			setCredentialSources:      []string{creds[1].GetPublicId()},
			resultCredentialSourceIds: []string{creds[1].GetPublicId()},
		},
		{
			name:                      "Set library on library populated target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated library-library", target.WithCredentialLibraries([]*target.CredentialLibrary{target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose)})),
			setCredentialSources:      []string{cls[1].GetPublicId()},
			resultCredentialSourceIds: []string{cls[1].GetPublicId()},
		},
		{
			name:                      "Set static on library populated target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated static-library", target.WithCredentialLibraries([]*target.CredentialLibrary{target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose)})),
			setCredentialSources:      []string{creds[1].GetPublicId()},
			resultCredentialSourceIds: []string{creds[1].GetPublicId()},
		},
		{
			name:                      "Set library on static populated target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated library-static", target.WithStaticCredentials([]*target.StaticCredential{target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose)})),
			setCredentialSources:      []string{cls[1].GetPublicId()},
			resultCredentialSourceIds: []string{cls[1].GetPublicId()},
		},
		{
			name:                      "Set static on static populated target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "populated static-static", target.WithStaticCredentials([]*target.StaticCredential{target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose)})),
			setCredentialSources:      []string{creds[1].GetPublicId()},
			resultCredentialSourceIds: []string{creds[1].GetPublicId()},
		},
		{
			name:                      "Set duplicate library on populated target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicate library", target.WithCredentialLibraries([]*target.CredentialLibrary{target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose)})),
			setCredentialSources:      []string{cls[1].GetPublicId(), cls[1].GetPublicId()},
			resultCredentialSourceIds: []string{cls[1].GetPublicId()},
		},
		{
			name:                      "Set duplicate static on populated target",
			tar:                       tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "duplicate static", target.WithStaticCredentials([]*target.StaticCredential{target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose)})),
			setCredentialSources:      []string{creds[1].GetPublicId(), creds[1].GetPublicId()},
			resultCredentialSourceIds: []string{creds[1].GetPublicId()},
		},
		{
			name: "Set empty on populated target",
			tar: tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "another populated",
				target.WithCredentialLibraries([]*target.CredentialLibrary{target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose)}),
				target.WithStaticCredentials([]*target.StaticCredential{target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose)})),
			setCredentialSources:      []string{},
			resultCredentialSourceIds: nil,
		},
	}
	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.SetTargetCredentialSourcesRequest{
				Id:                             tc.tar.GetPublicId(),
				Version:                        tc.tar.GetVersion(),
				ApplicationCredentialSourceIds: tc.setCredentialSources,
			}

			got, err := s.SetTargetCredentialSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.NoError(t, err, "Got error: %v", s)
			assert.ElementsMatch(t, tc.resultCredentialSourceIds, got.GetItem().GetApplicationCredentialSourceIds())
			assert.Equal(t, len(tc.resultCredentialSourceIds), len(got.GetItem().GetApplicationCredentialSources()))
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test name")

	failCases := []struct {
		name string
		req  *pbs.SetTargetCredentialSourcesRequest
		err  error
	}{
		{
			name: "Bad target Id",
			req: &pbs.SetTargetCredentialSourcesRequest{
				Id:                             "bad id",
				Version:                        tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.SetTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				Version:                        tar.GetVersion() + 3,
				ApplicationCredentialSourceIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad source id",
			req: &pbs.SetTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				Version:                        tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetTargetCredentialSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetTargetCredentialSources(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveTargetCredentialSources(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, context.Background(), conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	csVault := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	cls := vault.TestCredentialLibraries(t, conn, wrapper, csVault.GetPublicId(), 2)

	csStatic := credstatic.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	creds := credstatic.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", csStatic.GetPublicId(), proj.GetPublicId(), 2)

	ctx := context.Background()
	removeCases := []struct {
		name                      string
		tar                       target.Target
		removeCredentialSources   []string
		resultCredentialSourceIds []string
		wantErr                   bool
	}{
		{
			name:                    "Remove library from empty",
			tar:                     tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty lib"),
			removeCredentialSources: []string{cls[1].GetPublicId()},
			wantErr:                 true,
		},
		{
			name:                    "Remove static from empty",
			tar:                     tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "empty static"),
			removeCredentialSources: []string{creds[1].GetPublicId()},
			wantErr:                 true,
		},
		{
			name: "Remove 1 of 2 libraries",
			tar: tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove partial lib",
				target.WithCredentialLibraries([]*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", cls[1].GetPublicId(), credential.ApplicationPurpose),
				})),
			removeCredentialSources:   []string{cls[1].GetPublicId()},
			resultCredentialSourceIds: []string{cls[0].GetPublicId()},
		},
		{
			name: "Remove 1 of 2 static credentials",
			tar: tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove partial static",
				target.WithStaticCredentials([]*target.StaticCredential{
					target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewStaticCredential("", creds[1].GetPublicId(), credential.ApplicationPurpose),
				})),
			removeCredentialSources:   []string{creds[1].GetPublicId()},
			resultCredentialSourceIds: []string{creds[0].GetPublicId()},
		},
		{
			name: "Remove 1 duplicate set of 2 libraries",
			tar: tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove duplicate lib",
				target.WithCredentialLibraries([]*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", cls[1].GetPublicId(), credential.ApplicationPurpose),
				})),
			removeCredentialSources: []string{
				cls[1].GetPublicId(), cls[1].GetPublicId(),
			},
			resultCredentialSourceIds: []string{cls[0].GetPublicId()},
		},
		{
			name: "Remove 1 duplicate set of 2 static credentials",
			tar: tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove duplicate static",
				target.WithStaticCredentials([]*target.StaticCredential{
					target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewStaticCredential("", creds[1].GetPublicId(), credential.ApplicationPurpose),
				})),
			removeCredentialSources: []string{
				creds[1].GetPublicId(), creds[1].GetPublicId(),
			},
			resultCredentialSourceIds: []string{creds[0].GetPublicId()},
		},
		{
			name: "Remove mixed sources from target",
			tar: tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove mixed",
				target.WithCredentialLibraries([]*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", cls[1].GetPublicId(), credential.ApplicationPurpose),
				}),
				target.WithStaticCredentials([]*target.StaticCredential{
					target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewStaticCredential("", creds[1].GetPublicId(), credential.ApplicationPurpose),
				})),
			removeCredentialSources: []string{
				cls[1].GetPublicId(), creds[0].GetPublicId(),
			},
			resultCredentialSourceIds: []string{
				cls[0].GetPublicId(), creds[1].GetPublicId(),
			},
		},
		{
			name: "Remove all sources from target",
			tar: tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "remove all",
				target.WithCredentialLibraries([]*target.CredentialLibrary{
					target.TestNewCredentialLibrary("", cls[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewCredentialLibrary("", cls[1].GetPublicId(), credential.ApplicationPurpose),
				}),
				target.WithStaticCredentials([]*target.StaticCredential{
					target.TestNewStaticCredential("", creds[0].GetPublicId(), credential.ApplicationPurpose),
					target.TestNewStaticCredential("", creds[1].GetPublicId(), credential.ApplicationPurpose),
				})),
			removeCredentialSources: []string{
				cls[0].GetPublicId(), cls[1].GetPublicId(),
				creds[0].GetPublicId(), creds[1].GetPublicId(),
			},
			resultCredentialSourceIds: []string{},
		},
	}

	for _, tc := range removeCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.RemoveTargetCredentialSourcesRequest{
				Id:                             tc.tar.GetPublicId(),
				Version:                        tc.tar.GetVersion(),
				ApplicationCredentialSourceIds: tc.removeCredentialSources,
			}

			got, err := s.RemoveTargetCredentialSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultCredentialSourceIds, got.GetItem().GetApplicationCredentialSourceIds())
			assert.Equal(t, len(tc.resultCredentialSourceIds), len(got.GetItem().GetApplicationCredentialSources()))
		})
	}

	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "testing")

	failCases := []struct {
		name string
		req  *pbs.RemoveTargetCredentialSourcesRequest
		err  error
	}{
		{
			name: "Bad version",
			req: &pbs.RemoveTargetCredentialSourcesRequest{
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion() + 3,
				ApplicationCredentialSourceIds: []string{
					cls[0].GetPublicId(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad target Id",
			req: &pbs.RemoveTargetCredentialSourcesRequest{
				Id:      "bad id",
				Version: tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{
					cls[0].GetPublicId(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty sources",
			req: &pbs.RemoveTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				Version:                        tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid source ids",
			req: &pbs.RemoveTargetCredentialSourcesRequest{
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{
					"invalid",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveTargetCredentialSources(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveTargetCredentialSources(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestAuthorizeSession(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	err := vault.RegisterJobs(context.Background(), sche, rw, rw, kms)
	require.NoError(t, err)

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	staticRepo, err := static.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	staticHostRepoFn := func() (*static.Repository, error) {
		return staticRepo, nil
	}
	vaultCredRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}
	staticCredRepoFn := func() (*credstatic.Repository, error) {
		return credstatic.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}

	plg := host.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(plugin.TestPluginServer{
			ListHostsFn: func(_ context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
				var setIds []string
				for _, set := range req.GetSets() {
					setIds = append(setIds, set.GetId())
				}
				return &plgpb.ListHostsResponse{Hosts: []*plgpb.ListHostsResponseHost{
					{
						SetIds:      setIds,
						ExternalId:  "test",
						IpAddresses: []string{"10.0.0.1", "192.168.0.1"},
						DnsNames:    []string{"example.com"},
					},
					{
						SetIds:      setIds,
						ExternalId:  "test2",
						IpAddresses: []string{"10.1.1.1", "192.168.1.1"},
						DnsNames:    []string{"another-example.com"},
					},
				}}, nil
			},
		}),
	}
	pluginHostRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, plgm)
	}

	org, proj := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	ctx = auth.NewVerifierContext(requests.NewRequestContext(ctx),
		iamRepoFn,
		atRepoFn,
		serversRepoFn,
		kms,
		&authpb.RequestInfo{
			Token:       at.GetToken(),
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
		})

	r := iam.TestRole(t, conn, proj.GetPublicId())
	_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
	_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), "id=*;type=*;actions=*")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	shs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	_ = static.TestSetMembers(t, conn, shs.GetPublicId(), []*static.Host{h})

	hcWithPort := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hWithPort := static.TestHosts(t, conn, hcWithPort.GetPublicId(), 1)[0]
	shsWithPort := static.TestSets(t, conn, hcWithPort.GetPublicId(), 1)[0]
	_ = static.TestSetMembers(t, conn, shsWithPort.GetPublicId(), []*static.Host{hWithPort})
	hWithPort.Address = fmt.Sprintf("%s:54321", hWithPort.GetAddress())
	hWithPort, _, err = staticRepo.UpdateHost(ctx, hcWithPort.GetScopeId(), hWithPort, hWithPort.GetVersion(), []string{"address"})
	require.NoError(t, err)

	phc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	phs := plugin.TestSet(t, conn, kms, sche, phc, plgm, plugin.WithPreferredEndpoints([]string{"cidr:10.0.0.0/24"}))

	// Sync the boundary db from the plugins
	plugin.TestRunSetSync(t, conn, kms, plgm)

	v := vault.NewTestVaultServer(t)
	v.MountPKI(t)
	sec, tok := v.CreateToken(t, vault.WithPolicies([]string{"default", "boundary-controller", "pki"}))

	vaultStore := vault.TestCredentialStore(t, conn, wrapper, proj.GetPublicId(), v.Addr, tok, sec.Auth.Accessor)
	credService, err := credentiallibraries.NewService(vaultCredRepoFn, iamRepoFn)
	require.NoError(t, err)
	clsResp, err := credService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credlibpb.CredentialLibrary{
		CredentialStoreId: vaultStore.GetPublicId(),
		Name:              wrapperspb.String("Library Name"),
		Description:       wrapperspb.String("Library Description"),
		Attrs: &credlibpb.CredentialLibrary_VaultCredentialLibraryAttributes{
			VaultCredentialLibraryAttributes: &credlibpb.VaultCredentialLibraryAttributes{
				Path: &wrapperspb.StringValue{
					Value: path.Join("pki", "issue", "boundary"),
				},
				HttpMethod: &wrapperspb.StringValue{
					Value: "POST",
				},
				HttpRequestBody: &wrapperspb.StringValue{
					Value: `{"common_name":"boundary.com"}`,
				},
			},
		},
	}})
	require.NoError(t, err)

	const defaultPort = 2
	cases := []struct {
		name           string
		hostSourceId   string
		credSourceId   string
		wantedHostId   string
		wantedEndpoint string
	}{
		{
			name:           "static host",
			hostSourceId:   shs.GetPublicId(),
			credSourceId:   clsResp.GetItem().GetId(),
			wantedHostId:   h.GetPublicId(),
			wantedEndpoint: fmt.Sprintf("%s:%d", h.GetAddress(), defaultPort),
		},
		{
			name:           "static host with port defined",
			hostSourceId:   shsWithPort.GetPublicId(),
			credSourceId:   clsResp.GetItem().GetId(),
			wantedHostId:   hWithPort.GetPublicId(),
			wantedEndpoint: hWithPort.GetAddress(),
		},
		{
			name:           "plugin host",
			hostSourceId:   phs.GetPublicId(),
			credSourceId:   clsResp.GetItem().GetId(),
			wantedHostId:   "?",
			wantedEndpoint: fmt.Sprintf("10.0.0.1:%d", defaultPort),
		},
	}

	s, err := targets.NewService(ctx, kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, pluginHostRepoFn, staticHostRepoFn, vaultCredRepoFn, staticCredRepoFn)
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), tc.name, target.WithDefaultPort(defaultPort))
			apiTar, err := s.AddTargetHostSources(ctx, &pbs.AddTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion(),
				HostSourceIds: []string{tc.hostSourceId},
			})
			require.NoError(t, err)
			_, err = s.AddTargetCredentialSources(ctx,
				&pbs.AddTargetCredentialSourcesRequest{
					Id:                             tar.GetPublicId(),
					ApplicationCredentialSourceIds: []string{clsResp.GetItem().GetId()},
					Version:                        apiTar.GetItem().GetVersion(),
				})
			require.NoError(t, err)

			// Tell our DB that there is a worker ready to serve the data
			server.TestKmsWorker(t, conn, wrapper)

			asRes1, err := s.AuthorizeSession(ctx, &pbs.AuthorizeSessionRequest{
				Id: tar.GetPublicId(),
			})
			require.NoError(t, err)
			asRes2, err := s.AuthorizeSession(ctx, &pbs.AuthorizeSessionRequest{
				Id: tar.GetPublicId(),
			})
			require.NoError(t, err)
			assert.NotEmpty(t, cmp.Diff(asRes1.GetItem().GetCredentials(), asRes2.GetItem().GetCredentials(), protocmp.Transform()),
				"the credentials aren't unique per request authorized session")

			_, err = s.AuthorizeSession(ctx, &pbs.AuthorizeSessionRequest{
				Id:     tar.GetPublicId(),
				HostId: asRes2.GetItem().GetHostId(),
			})
			require.NoError(t, err, "session must authorize with explicit host ID")

			wantedHostId := tc.wantedHostId
			if tc.wantedHostId == "?" {
				wantedHostId = asRes2.GetItem().GetHostId()
			}

			want := &pb.SessionAuthorization{
				Scope: &scopes.ScopeInfo{
					Id:            proj.GetPublicId(),
					Type:          proj.GetType(),
					Name:          proj.GetName(),
					Description:   proj.GetDescription(),
					ParentScopeId: proj.GetParentId(),
				},
				TargetId:  tar.GetPublicId(),
				UserId:    at.GetIamUserId(),
				HostSetId: tc.hostSourceId,
				HostId:    wantedHostId,
				Type:      "tcp",
				Endpoint:  fmt.Sprintf("tcp://%s", tc.wantedEndpoint),
				Credentials: []*pb.SessionCredential{{
					CredentialSource: &pb.CredentialSource{
						Id:                clsResp.GetItem().GetId(),
						Name:              clsResp.GetItem().GetName().GetValue(),
						Description:       clsResp.GetItem().GetDescription().GetValue(),
						CredentialStoreId: vaultStore.GetPublicId(),
						Type:              vault.Subtype.String(),
					},
				}},
				// TODO: validate the contents of the authorization token is what is expected
			}
			wantSecret := map[string]interface{}{
				"certificate":      "-----BEGIN CERTIFICATE-----\n",
				"issuing_ca":       "-----BEGIN CERTIFICATE-----\n",
				"private_key":      "-----BEGIN RSA PRIVATE KEY-----\n",
				"private_key_type": "rsa",
			}
			got := asRes1.GetItem()

			require.Len(t, got.GetCredentials(), 1)

			gotCred := got.Credentials[0]
			require.NotNil(t, gotCred.Secret)
			assert.NotEmpty(t, gotCred.Secret.Raw)
			dSec := decodeJsonSecret(t, gotCred.Secret.Raw)
			require.NoError(t, err)
			require.Equal(t, dSec, gotCred.Secret.Decoded.AsMap())
			for k, v := range wantSecret {
				gotV, ok := dSec[k]
				require.True(t, ok)
				assert.Truef(t, strings.HasPrefix(gotV.(string), v.(string)), "%q:%q doesn't have prefix %q", k, gotV, v)
			}
			gotCred.Secret = nil

			got.AuthorizationToken, got.SessionId, got.CreatedTime = "", "", nil
			assert.Empty(t, cmp.Diff(got, want, protocmp.Transform()))
		})
	}
}

func TestAuthorizeSessionTypedCredentials(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	err := vault.RegisterJobs(context.Background(), sche, rw, rw, kms)
	require.NoError(t, err)

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	staticHostRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	vaultCredRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}
	staticCredRepoFn := func() (*credstatic.Repository, error) {
		return credstatic.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	pluginHostRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}

	org, proj := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	ctx = auth.NewVerifierContext(requests.NewRequestContext(ctx),
		iamRepoFn,
		atRepoFn,
		serversRepoFn,
		kms,
		&authpb.RequestInfo{
			Token:       at.GetToken(),
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
		})

	r := iam.TestRole(t, conn, proj.GetPublicId())
	_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
	_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), "id=*;type=*;actions=*")

	s, err := targets.NewService(ctx, kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, pluginHostRepoFn, staticHostRepoFn, vaultCredRepoFn, staticCredRepoFn)
	require.NoError(t, err)

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	shs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	_ = static.TestSetMembers(t, conn, shs.GetPublicId(), []*static.Host{h})

	v := vault.NewTestVaultServer(t)
	v.AddKVPolicy(t)
	sec, tok := v.CreateToken(t, vault.WithPolicies([]string{"default", "boundary-controller", "secret"}))

	vaultStore := vault.TestCredentialStore(t, conn, wrapper, proj.GetPublicId(), v.Addr, tok, sec.Auth.Accessor)
	credLibService, err := credentiallibraries.NewService(vaultCredRepoFn, iamRepoFn)
	require.NoError(t, err)

	// Create secret in vault with default username and password fields
	defaultUserPass := v.CreateKVSecret(t, "default-userpass", []byte(`{"data": {"username": "my-user", "password": "my-pass"}}`))
	require.NotNil(t, defaultUserPass)

	clsRespUsernamePassword, err := credLibService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credlibpb.CredentialLibrary{
		CredentialStoreId: vaultStore.GetPublicId(),
		Name:              wrapperspb.String("Usernamepassword Library"),
		Description:       wrapperspb.String("Usernamepassword Library Description"),
		Attrs: &credlibpb.CredentialLibrary_VaultCredentialLibraryAttributes{
			VaultCredentialLibraryAttributes: &credlibpb.VaultCredentialLibraryAttributes{
				Path:       wrapperspb.String(path.Join("secret", "data", "default-userpass")),
				HttpMethod: wrapperspb.String("GET"),
			},
		},
		CredentialType: "username_password",
	}})
	require.NoError(t, err)

	clsRespUnspecified, err := credLibService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credlibpb.CredentialLibrary{
		CredentialStoreId: vaultStore.GetPublicId(),
		Name:              wrapperspb.String("Unspecified Library"),
		Description:       wrapperspb.String("Unspecified Library Description"),
		Attrs: &credlibpb.CredentialLibrary_VaultCredentialLibraryAttributes{
			VaultCredentialLibraryAttributes: &credlibpb.VaultCredentialLibraryAttributes{
				Path:       wrapperspb.String(path.Join("secret", "data", "default-userpass")),
				HttpMethod: wrapperspb.String("GET"),
			},
		},
	}})
	require.NoError(t, err)

	// Create secret in vault with non default username and password fields
	nonDefaultUserPass := v.CreateKVSecret(t, "non-default-userpass", []byte(`{"data": {"non-default-user": "my-user", "non-default-pass": "my-pass"}}`))
	require.NotNil(t, nonDefaultUserPass)

	clsRespUsernamePasswordWithMapping, err := credLibService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credlibpb.CredentialLibrary{
		CredentialStoreId: vaultStore.GetPublicId(),
		Name:              wrapperspb.String("Usernamepassword Mapping Library"),
		Description:       wrapperspb.String("Usernamepassword Mapping Library Description"),
		Attrs: &credlibpb.CredentialLibrary_VaultCredentialLibraryAttributes{
			VaultCredentialLibraryAttributes: &credlibpb.VaultCredentialLibraryAttributes{
				Path:       wrapperspb.String(path.Join("secret", "data", "non-default-userpass")),
				HttpMethod: wrapperspb.String("GET"),
			},
		},
		CredentialType: "username_password",
		CredentialMappingOverrides: &structpb.Struct{Fields: map[string]*structpb.Value{
			"username_attribute": structpb.NewStringValue("non-default-user"),
			"password_attribute": structpb.NewStringValue("non-default-pass"),
		}},
	}})
	require.NoError(t, err)

	staticStore := credstatic.TestCredentialStore(t, conn, wrapper, proj.GetPublicId())
	credService, err := credentials.NewService(staticCredRepoFn, iamRepoFn)
	require.NoError(t, err)
	credResp, err := credService.CreateCredential(ctx, &pbs.CreateCredentialRequest{Item: &credpb.Credential{
		CredentialStoreId: staticStore.GetPublicId(),
		Type:              credstatic.UsernamePasswordSubtype.String(),
		Name:              wrapperspb.String("Cred Name"),
		Description:       wrapperspb.String("Cred Description"),
		Attrs: &credpb.Credential_UsernamePasswordAttributes{
			UsernamePasswordAttributes: &credpb.UsernamePasswordAttributes{
				Username: wrapperspb.String("static-username"),
				Password: wrapperspb.String("static-password"),
			},
		},
	}})
	require.NoError(t, err)
	require.NotNil(t, credResp)

	cases := []struct {
		name           string
		hostSourceId   string
		credSourceId   string
		wantedHostId   string
		wantedEndpoint string
		wantedCred     *pb.SessionCredential
	}{
		{
			name:           "vault-unspecified",
			hostSourceId:   shs.GetPublicId(),
			credSourceId:   clsRespUnspecified.GetItem().GetId(),
			wantedHostId:   h.GetPublicId(),
			wantedEndpoint: h.GetAddress(),
			wantedCred: &pb.SessionCredential{
				CredentialSource: &pb.CredentialSource{
					Id:                clsRespUnspecified.GetItem().GetId(),
					Name:              clsRespUnspecified.GetItem().GetName().GetValue(),
					Description:       clsRespUnspecified.GetItem().GetDescription().GetValue(),
					CredentialStoreId: vaultStore.GetPublicId(),
					Type:              vault.Subtype.String(),
				},
			},
		},
		{
			name:           "vault-usernamepassword",
			hostSourceId:   shs.GetPublicId(),
			credSourceId:   clsRespUsernamePassword.GetItem().GetId(),
			wantedHostId:   h.GetPublicId(),
			wantedEndpoint: h.GetAddress(),
			wantedCred: &pb.SessionCredential{
				CredentialSource: &pb.CredentialSource{
					Id:                clsRespUsernamePassword.GetItem().GetId(),
					Name:              clsRespUsernamePassword.GetItem().GetName().GetValue(),
					Description:       clsRespUsernamePassword.GetItem().GetDescription().GetValue(),
					CredentialStoreId: vaultStore.GetPublicId(),
					Type:              vault.Subtype.String(),
					CredentialType:    string(credential.UsernamePasswordType),
				},
				Credential: func() *structpb.Struct {
					data := map[string]interface{}{
						"password": "my-pass",
						"username": "my-user",
					}
					st, err := structpb.NewStruct(data)
					require.NoError(t, err)
					return st
				}(),
			},
		},
		{
			name:           "vault-UsernamePassword-with-mapping",
			hostSourceId:   shs.GetPublicId(),
			credSourceId:   clsRespUsernamePasswordWithMapping.GetItem().GetId(),
			wantedHostId:   h.GetPublicId(),
			wantedEndpoint: h.GetAddress(),
			wantedCred: &pb.SessionCredential{
				CredentialSource: &pb.CredentialSource{
					Id:                clsRespUsernamePasswordWithMapping.GetItem().GetId(),
					Name:              clsRespUsernamePasswordWithMapping.GetItem().GetName().GetValue(),
					Description:       clsRespUsernamePasswordWithMapping.GetItem().GetDescription().GetValue(),
					CredentialStoreId: vaultStore.GetPublicId(),
					Type:              vault.Subtype.String(),
					CredentialType:    string(credential.UsernamePasswordType),
				},
				Credential: func() *structpb.Struct {
					data := map[string]interface{}{
						"password": "my-pass",
						"username": "my-user",
					}
					st, err := structpb.NewStruct(data)
					require.NoError(t, err)
					return st
				}(),
			},
		},
		{
			name:           "static-UsernamePassword",
			hostSourceId:   shs.GetPublicId(),
			credSourceId:   credResp.GetItem().GetId(),
			wantedHostId:   h.GetPublicId(),
			wantedEndpoint: h.GetAddress(),
			wantedCred: &pb.SessionCredential{
				CredentialSource: &pb.CredentialSource{
					Id:                credResp.GetItem().GetId(),
					Name:              credResp.GetItem().GetName().GetValue(),
					Description:       credResp.GetItem().GetDescription().GetValue(),
					CredentialStoreId: staticStore.GetPublicId(),
					Type:              credstatic.Subtype.String(),
					CredentialType:    string(credential.UsernamePasswordType),
				},
				Credential: func() *structpb.Struct {
					data := map[string]interface{}{
						"password": "static-password",
						"username": "static-username",
					}
					st, err := structpb.NewStruct(data)
					require.NoError(t, err)
					return st
				}(),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const defaultPort = 2
			tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), tc.name, target.WithDefaultPort(defaultPort))
			apiTar, err := s.AddTargetHostSources(ctx, &pbs.AddTargetHostSourcesRequest{
				Id:            tar.GetPublicId(),
				Version:       tar.GetVersion(),
				HostSourceIds: []string{tc.hostSourceId},
			})
			require.NoError(t, err)
			_, err = s.AddTargetCredentialSources(ctx,
				&pbs.AddTargetCredentialSourcesRequest{
					Id:                             tar.GetPublicId(),
					ApplicationCredentialSourceIds: []string{tc.credSourceId},
					Version:                        apiTar.GetItem().GetVersion(),
				})
			require.NoError(t, err)

			// Tell our DB that there is a worker ready to serve the data
			server.TestKmsWorker(t, conn, wrapper)

			asRes, err := s.AuthorizeSession(ctx, &pbs.AuthorizeSessionRequest{
				Id: tar.GetPublicId(),
			})
			require.NoError(t, err)

			want := &pb.SessionAuthorization{
				Scope: &scopes.ScopeInfo{
					Id:            proj.GetPublicId(),
					Type:          proj.GetType(),
					Name:          proj.GetName(),
					Description:   proj.GetDescription(),
					ParentScopeId: proj.GetParentId(),
				},
				TargetId:    tar.GetPublicId(),
				UserId:      at.GetIamUserId(),
				HostSetId:   tc.hostSourceId,
				HostId:      tc.wantedHostId,
				Type:        "tcp",
				Endpoint:    fmt.Sprintf("tcp://%s:%d", tc.wantedEndpoint, defaultPort),
				Credentials: []*pb.SessionCredential{tc.wantedCred},
				// TODO: validate the contents of the authorization token is what is expected
			}
			got := asRes.GetItem()

			require.Len(t, got.GetCredentials(), 1)

			gotCred := got.Credentials[0]
			require.NotNil(t, gotCred.Secret)
			assert.NotEmpty(t, gotCred.Secret.Raw)

			gotCred.Secret = nil
			got.AuthorizationToken, got.SessionId, got.CreatedTime = "", "", nil
			assert.Empty(t, cmp.Diff(got, want, protocmp.Transform()))
		})
	}
}

func TestAuthorizeSession_Errors(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	err := vault.RegisterJobs(context.Background(), sche, rw, rw, kms)
	require.NoError(t, err)

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	staticHostRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	vaultCredRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}
	staticCredRepoFn := func() (*credstatic.Repository, error) {
		return credstatic.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	org, proj := iam.TestScopes(t, iamRepo)

	s, err := targets.NewService(ctx, kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, pluginHostRepoFn, staticHostRepoFn, vaultCredRepoFn, staticCredRepoFn)
	require.NoError(t, err)

	// Authorized user gets full permissions
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	ctx = auth.NewVerifierContext(requests.NewRequestContext(context.Background()),
		iamRepoFn,
		atRepoFn,
		serversRepoFn,
		kms,
		&authpb.RequestInfo{
			Token:       at.GetToken(),
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
		})
	r := iam.TestRole(t, conn, proj.GetPublicId())
	_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
	_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), "id=*;type=*;actions=*")

	v := vault.NewTestVaultServer(t, vault.WithDockerNetwork(true))
	v.MountDatabase(t)
	sec, tok := v.CreateToken(t, vault.WithPolicies([]string{"default", "database"}))
	store := vault.TestCredentialStore(t, conn, wrapper, proj.GetPublicId(), v.Addr, tok, sec.Auth.Accessor)

	workerExists := func(tar target.Target) (version uint32) {
		server.TestKmsWorker(t, conn, wrapper)
		return tar.GetVersion()
	}

	hostSetNoHostExists := func(tar target.Target) (version uint32) {
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

		tr, err := s.AddTargetHostSources(ctx, &pbs.AddTargetHostSourcesRequest{
			Id:            tar.GetPublicId(),
			Version:       tar.GetVersion(),
			HostSourceIds: []string{hs.GetPublicId()},
		})
		require.NoError(t, err)
		return tr.GetItem().GetVersion()
	}

	hostExists := func(tar target.Target) (version uint32) {
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		_ = static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		apiTar, err := s.AddTargetHostSources(ctx, &pbs.AddTargetHostSourcesRequest{
			Id:            tar.GetPublicId(),
			Version:       tar.GetVersion(),
			HostSourceIds: []string{hs.GetPublicId()},
		})
		require.NoError(t, err)
		h.Address = fmt.Sprintf("%s:54321", h.GetAddress())
		repo, err := staticHostRepoFn()
		require.NoError(t, err)
		h, _, err = repo.UpdateHost(ctx, hc.GetScopeId(), h, h.GetVersion(), []string{"address"})
		require.NoError(t, err)
		return apiTar.GetItem().GetVersion()
	}

	hostWithoutPort := func(tar target.Target) (version uint32) {
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		_ = static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		apiTar, err := s.AddTargetHostSources(ctx, &pbs.AddTargetHostSourcesRequest{
			Id:            tar.GetPublicId(),
			Version:       tar.GetVersion(),
			HostSourceIds: []string{hs.GetPublicId()},
		})
		require.NoError(t, err)
		return apiTar.GetItem().GetVersion()
	}

	libraryExists := func(tar target.Target) (version uint32) {
		credService, err := credentiallibraries.NewService(vaultCredRepoFn, iamRepoFn)
		require.NoError(t, err)
		clsResp, err := credService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credlibpb.CredentialLibrary{
			CredentialStoreId: store.GetPublicId(),
			Description:       wrapperspb.String(fmt.Sprintf("Library Description for target %q", tar.GetName())),
			Attrs: &credlibpb.CredentialLibrary_VaultCredentialLibraryAttributes{
				VaultCredentialLibraryAttributes: &credlibpb.VaultCredentialLibraryAttributes{
					Path: wrapperspb.String(path.Join("database", "creds", "opened")),
				},
			},
		}})
		require.NoError(t, err)

		tr, err := s.AddTargetCredentialSources(ctx,
			&pbs.AddTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				ApplicationCredentialSourceIds: []string{clsResp.GetItem().GetId()},
				Version:                        tar.GetVersion(),
			})
		require.NoError(t, err)
		return tr.GetItem().GetVersion()
	}

	misConfiguredlibraryExists := func(tar target.Target) (version uint32) {
		credService, err := credentiallibraries.NewService(vaultCredRepoFn, iamRepoFn)
		require.NoError(t, err)
		clsResp, err := credService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credlibpb.CredentialLibrary{
			CredentialStoreId: store.GetPublicId(),
			Description:       wrapperspb.String(fmt.Sprintf("Library Description for target %q", tar.GetName())),
			Attrs: &credlibpb.CredentialLibrary_VaultCredentialLibraryAttributes{
				VaultCredentialLibraryAttributes: &credlibpb.VaultCredentialLibraryAttributes{
					Path: wrapperspb.String("bad path"),
				},
			},
		}})
		require.NoError(t, err)

		tr, err := s.AddTargetCredentialSources(ctx,
			&pbs.AddTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				ApplicationCredentialSourceIds: []string{clsResp.GetItem().GetId()},
				Version:                        tar.GetVersion(),
			})
		require.NoError(t, err)
		return tr.GetItem().GetVersion()
	}

	cases := []struct {
		name  string
		setup []func(target.Target) uint32
		err   bool
	}{
		{
			// This one must be run first since it relies on the DB not having any worker details
			name:  "no worker",
			setup: []func(tcpTarget target.Target) uint32{hostExists, libraryExists},
			err:   true,
		},
		{
			name:  "success",
			setup: []func(tcpTarget target.Target) uint32{workerExists, hostExists, libraryExists},
		},
		{
			name:  "no port",
			setup: []func(tcpTarget target.Target) uint32{workerExists, hostWithoutPort, libraryExists},
			err:   true,
		},
		{
			name:  "no hosts",
			setup: []func(tcpTarget target.Target) uint32{workerExists, hostSetNoHostExists, libraryExists},
			err:   true,
		},
		{
			name:  "bad library configuration",
			setup: []func(tcpTarget target.Target) uint32{workerExists, hostExists, misConfiguredlibraryExists},
			err:   true,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), fmt.Sprintf("test-%d", i))

			for _, fn := range tc.setup {
				ver := fn(tar)
				tar.SetVersion(ver)
			}

			res, err := s.AuthorizeSession(ctx, &pbs.AuthorizeSessionRequest{
				Id: tar.GetPublicId(),
			})
			if tc.err {
				require.Error(t, err)
				require.Nil(t, res)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
		})
	}
}

func decodeJsonSecret(t *testing.T, in string) map[string]interface{} {
	t.Helper()
	ret := make(map[string]interface{})
	dec := json.NewDecoder(base64.NewDecoder(base64.StdEncoding, strings.NewReader(in)))
	require.NoError(t, dec.Decode(&ret))
	return ret
}

// Test that deprecated action add-credential-libraries still works
// TODO: this test can be removed when grants are migrated
func TestAddTargetCredentialLibraryPerms(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	org, proj := iam.TestScopes(t, iamRepo)

	storeStatic := credstatic.TestCredentialStore(t, conn, wrapper, proj.GetPublicId())
	cred := credstatic.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", storeStatic.GetPublicId(), proj.GetPublicId())

	cases := []struct {
		name    string
		grant   string
		wantErr bool
	}{
		{
			name:  "valid-deprecated",
			grant: "id=*;type=*;actions=add-credential-libraries",
		},
		{
			name:    "invalid",
			grant:   "id=*;type=*;actions=authorize-session",
			wantErr: true,
		},
		{
			name:  "valid-sources",
			grant: "id=*;type=*;actions=add-credential-sources",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
			ctx := auth.NewVerifierContext(requests.NewRequestContext(context.Background()),
				iamRepoFn,
				atRepoFn,
				serversRepoFn,
				kms,
				&authpb.RequestInfo{
					Token:       at.GetToken(),
					TokenFormat: uint32(auth.AuthTokenTypeBearer),
					PublicId:    at.GetPublicId(),
				})

			r := iam.TestRole(t, conn, proj.GetPublicId())
			_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
			_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), tc.grant)

			s, err := testService(t, context.Background(), conn, kms, wrapper)
			require.NoError(t, err)

			tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), tc.name)
			req := &pbs.AddTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				Version:                        tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{cred.GetPublicId()},
			}

			got, err := s.AddTargetCredentialSources(ctx, req)
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			status, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", status)
			require.NotNil(t, got)
		})
	}
}

// Test that deprecated action add-credential-libraries still works
// TODO: this test can be removed when grants are migrated
func TestSetTargetCredentialLibraryPerms(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	org, proj := iam.TestScopes(t, iamRepo)

	storeStatic := credstatic.TestCredentialStore(t, conn, wrapper, proj.GetPublicId())
	cred := credstatic.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", storeStatic.GetPublicId(), proj.GetPublicId())

	cases := []struct {
		name    string
		grant   string
		wantErr bool
	}{
		{
			name:  "valid-deprecated",
			grant: "id=*;type=*;actions=set-credential-libraries",
		},
		{
			name:    "invalid",
			grant:   "id=*;type=*;actions=authorize-session",
			wantErr: true,
		},
		{
			name:  "valid-sources",
			grant: "id=*;type=*;actions=set-credential-sources",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
			ctx := auth.NewVerifierContext(requests.NewRequestContext(context.Background()),
				iamRepoFn,
				atRepoFn,
				serversRepoFn,
				kms,
				&authpb.RequestInfo{
					Token:       at.GetToken(),
					TokenFormat: uint32(auth.AuthTokenTypeBearer),
					PublicId:    at.GetPublicId(),
				})

			r := iam.TestRole(t, conn, proj.GetPublicId())
			_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
			_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), tc.grant)

			s, err := testService(t, context.Background(), conn, kms, wrapper)
			require.NoError(t, err)

			tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), tc.name)
			req := &pbs.SetTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				Version:                        tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{cred.GetPublicId()},
			}

			got, err := s.SetTargetCredentialSources(ctx, req)
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			status, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", status)
			require.NotNil(t, got)
		})
	}
}

// Test that deprecated action remove-credential-libraries still works
// TODO: this test can be removed when grants are migrated
func TestRemoveTargetCredentialLibraryPerms(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	org, proj := iam.TestScopes(t, iamRepo)

	storeStatic := credstatic.TestCredentialStore(t, conn, wrapper, proj.GetPublicId())
	cred := credstatic.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", storeStatic.GetPublicId(), proj.GetPublicId())

	cases := []struct {
		name    string
		grant   string
		wantErr bool
	}{
		{
			name:  "valid-deprecated",
			grant: "id=*;type=*;actions=remove-credential-libraries",
		},
		{
			name:    "invalid",
			grant:   "id=*;type=*;actions=authorize-session",
			wantErr: true,
		},
		{
			name:  "valid-sources",
			grant: "id=*;type=*;actions=remove-credential-sources",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
			ctx := auth.NewVerifierContext(requests.NewRequestContext(context.Background()),
				iamRepoFn,
				atRepoFn,
				serversRepoFn,
				kms,
				&authpb.RequestInfo{
					Token:       at.GetToken(),
					TokenFormat: uint32(auth.AuthTokenTypeBearer),
					PublicId:    at.GetPublicId(),
				})

			r := iam.TestRole(t, conn, proj.GetPublicId())
			_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
			_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), tc.grant)

			s, err := testService(t, context.Background(), conn, kms, wrapper)
			require.NoError(t, err)

			tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), tc.name, target.WithStaticCredentials([]*target.StaticCredential{
				target.TestNewStaticCredential("", cred.GetPublicId(), credential.ApplicationPurpose),
			}))

			req := &pbs.RemoveTargetCredentialSourcesRequest{
				Id:                             tar.GetPublicId(),
				Version:                        tar.GetVersion(),
				ApplicationCredentialSourceIds: []string{cred.GetPublicId()},
			}

			got, err := s.RemoveTargetCredentialSources(ctx, req)
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			status, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", status)
			require.NotNil(t, got)
		})
	}
}
