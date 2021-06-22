package targets_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	credpb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	spbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/servers"
	spb "github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/credentiallibraries"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/workers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/jinzhu/gorm"
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
)

var testAuthorizedActions = []string{
	"no-op",
	"read",
	"update",
	"delete",
	"add-host-sets",
	"set-host-sets",
	"remove-host-sets",
	"add-credential-libraries",
	"set-credential-libraries",
	"remove-credential-libraries",
	"authorize-session",
}

func testService(t *testing.T, conn *gorm.DB, kms *kms.Kms, wrapper wrapping.Wrapper) (targets.Service, error) {
	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	serversRepoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	staticHostRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	credentialRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}
	return targets.NewService(kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, staticHostRepoFn, credentialRepoFn)
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

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test", target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()}))

	pTar := &pb.Target{
		Id:                     tar.GetPublicId(),
		ScopeId:                proj.GetPublicId(),
		Name:                   wrapperspb.String("test"),
		CreatedTime:            tar.CreateTime.GetTimestamp(),
		UpdatedTime:            tar.UpdateTime.GetTimestamp(),
		Scope:                  &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
		Type:                   target.TcpTargetType.String(),
		HostSetIds:             []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		Attributes:             new(structpb.Struct),
		SessionMaxSeconds:      wrapperspb.UInt32(28800),
		SessionConnectionLimit: wrapperspb.Int32(1),
		AuthorizedActions:      testAuthorizedActions,
	}
	for _, ihs := range hs {
		pTar.HostSets = append(pTar.HostSets, &pb.HostSet{Id: ihs.GetPublicId(), HostCatalogId: ihs.GetCatalogId()})
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
			req:  &pbs.GetTargetRequest{Id: target.TcpTargetPrefix + "_DoesntExis"},
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
			req:  &pbs.GetTargetRequest{Id: target.TcpTargetPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := testService(t, conn, kms, wrapper)
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

	var wantTars []*pb.Target
	var totalTars []*pb.Target
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("tar%d", i)
		tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), name, target.WithHostSets([]string{hss[0].GetPublicId(), hss[1].GetPublicId()}))
		wantTars = append(wantTars, &pb.Target{
			Id:                     tar.GetPublicId(),
			ScopeId:                proj.GetPublicId(),
			Name:                   wrapperspb.String(name),
			Scope:                  &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
			CreatedTime:            tar.GetCreateTime().GetTimestamp(),
			UpdatedTime:            tar.GetUpdateTime().GetTimestamp(),
			Version:                tar.GetVersion(),
			Type:                   target.TcpTargetType.String(),
			Attributes:             new(structpb.Struct),
			SessionMaxSeconds:      wrapperspb.UInt32(28800),
			SessionConnectionLimit: wrapperspb.Int32(1),
			AuthorizedActions:      testAuthorizedActions,
		})
		totalTars = append(totalTars, wantTars[i])
		tar = target.TestTcpTarget(t, conn, otherProj.GetPublicId(), name, target.WithHostSets([]string{otherHss[0].GetPublicId(), otherHss[1].GetPublicId()}))
		totalTars = append(totalTars, &pb.Target{
			Id:                     tar.GetPublicId(),
			ScopeId:                otherProj.GetPublicId(),
			Name:                   wrapperspb.String(name),
			Scope:                  &scopes.ScopeInfo{Id: otherProj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: otherOrg.GetPublicId()},
			CreatedTime:            tar.GetCreateTime().GetTimestamp(),
			UpdatedTime:            tar.GetUpdateTime().GetTimestamp(),
			Version:                tar.GetVersion(),
			Type:                   target.TcpTargetType.String(),
			Attributes:             new(structpb.Struct),
			SessionMaxSeconds:      wrapperspb.UInt32(28800),
			SessionConnectionLimit: wrapperspb.Int32(1),
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
			s, err := testService(t, conn, kms, wrapper)
			require.NoError(err, "Couldn't create new host set service.")

			// Test with non-anon user
			got, gErr := s.ListTargets(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListTargets(%q) got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListTargets(%q) scope %q, got response %q, wanted %q", tc.name, tc.req.GetScopeId(), got, tc.res)

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
				require.Nil(item.Attributes)
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

	_, proj := iam.TestScopes(t, iamRepo)
	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test")

	s, err := testService(t, conn, kms, wrapper)
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
				Id: target.TcpTargetPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad target id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteTargetRequest{
				Id: target.TcpTargetPrefix + "_bad_format",
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

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test")

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(err, "Couldn't create a new target service.")
	req := &pbs.DeleteTargetRequest{
		Id: tar.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())
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
				Type:        target.TcpTargetType.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"default_port": structpb.NewNumberValue(2),
				}},
				WorkerFilter: wrapperspb.String(`type == "bar"`),
			}},
			res: &pbs.CreateTargetResponse{
				Uri: fmt.Sprintf("targets/%s_", target.TcpTargetPrefix),
				Item: &pb.Target{
					ScopeId:     proj.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					Type:        target.TcpTargetType.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(2),
					}},
					SessionMaxSeconds:      wrapperspb.UInt32(28800),
					SessionConnectionLimit: wrapperspb.Int32(1),
					AuthorizedActions:      testAuthorizedActions,
					WorkerFilter:           wrapperspb.String(`type == "bar"`),
				},
			},
		},
		{
			name: "Create with default port 0",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Name:        wrapperspb.String("name"),
				Description: wrapperspb.String("desc"),
				Type:        target.TcpTargetType.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"default_port": structpb.NewNumberValue(0),
				}},
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

			s, err := testService(t, conn, kms, wrapper)
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
				assert.True(strings.HasPrefix(got.GetItem().GetId(), target.TcpTargetPrefix), got.GetItem().GetId())

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

	tar, err := target.NewTcpTarget(proj.GetPublicId(), target.WithName("default"), target.WithDescription("default"))
	tar.DefaultPort = 2
	require.NoError(t, err)
	gtar, _, _, err := repo.CreateTcpTarget(context.Background(), tar, target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()}))
	require.NoError(t, err)
	tar = gtar.(*target.TcpTarget)

	var version uint32 = 1

	resetTarget := func() {
		version++
		_, _, _, _, err = repo.UpdateTcpTarget(context.Background(), tar, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset target.")
		version++
	}

	hCreated := tar.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateTargetRequest{
		Id: tar.GetPublicId(),
	}

	tested, err := testService(t, conn, kms, wrapper)
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
					Type:                   target.TcpSubtype.String(),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					Type:        target.TcpTargetType.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(2),
					}},
					CreatedTime:            tar.GetCreateTime().GetTimestamp(),
					HostSetIds:             hsIds,
					HostSets:               hostSets,
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
					Type:        target.TcpSubtype.String(),
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
					Type:        target.TcpTargetType.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(2),
					}},
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					SessionMaxSeconds:      wrapperspb.UInt32(3600),
					SessionConnectionLimit: wrapperspb.Int32(5),
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
				UpdateMask: &field_mask.FieldMask{Paths: []string{"default_port"}},
				Item: &pb.Target{
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(0),
					}},
				},
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
					Type:        target.TcpTargetType.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(2),
					}},
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					SessionMaxSeconds:      wrapperspb.UInt32(3600),
					SessionConnectionLimit: wrapperspb.Int32(5),
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
					Type:        target.TcpTargetType.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(2),
					}},
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					SessionMaxSeconds:      wrapperspb.UInt32(3600),
					SessionConnectionLimit: wrapperspb.Int32(5),
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
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(2),
					}},
					Type:                   target.TcpTargetType.String(),
					HostSetIds:             hsIds,
					HostSets:               hostSets,
					SessionMaxSeconds:      wrapperspb.UInt32(3600),
					SessionConnectionLimit: wrapperspb.Int32(5),
					AuthorizedActions:      testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Target",
			req: &pbs.UpdateTargetRequest{
				Id: target.TcpTargetPrefix + "_DoesntExis",
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
			assert, require := assert.New(t), require.New(t)
			tc.req.Item.Version = version

			req := proto.Clone(toMerge).(*pbs.UpdateTargetRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateTarget(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateTarget(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetTarget()
			}

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
				tc.res.Item.Version = version + 1
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

	tar, err := target.NewTcpTarget(proj.GetPublicId(), target.WithName("default"), target.WithDescription("default"))
	tar.DefaultPort = 2
	require.NoError(t, err)
	gtar, _, _, err := repo.CreateTcpTarget(context.Background(), tar)
	require.NoError(t, err)

	tested, err := testService(t, conn, kms, wrapper)
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

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	addCases := []struct {
		name           string
		tar            *target.TcpTarget
		addHostSets    []string
		resultHostSets []string
	}{
		{
			name:           "Add set on empty target",
			tar:            target.TestTcpTarget(t, conn, proj.GetPublicId(), "empty"),
			addHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Add set on populated target",
			tar:            target.TestTcpTarget(t, conn, proj.GetPublicId(), "populated", target.WithHostSets([]string{hs[0].GetPublicId()})),
			addHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
		{
			name:           "Add duplicated sets on populated target",
			tar:            target.TestTcpTarget(t, conn, proj.GetPublicId(), "duplicated", target.WithHostSets([]string{hs[0].GetPublicId()})),
			addHostSets:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHostSets: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
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

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test")

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

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	setCases := []struct {
		name           string
		tar            *target.TcpTarget
		setHostSets    []string
		resultHostSets []string
	}{
		{
			name:           "Set on empty target",
			tar:            target.TestTcpTarget(t, conn, proj.GetPublicId(), "empty"),
			setHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Set on populated target",
			tar:            target.TestTcpTarget(t, conn, proj.GetPublicId(), "populated", target.WithHostSets([]string{hs[0].GetPublicId()})),
			setHostSets:    []string{hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Set duplicate host set on populated target",
			tar:            target.TestTcpTarget(t, conn, proj.GetPublicId(), "duplicate", target.WithHostSets([]string{hs[0].GetPublicId()})),
			setHostSets:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHostSets: []string{hs[1].GetPublicId()},
		},
		{
			name:           "Set empty on populated target",
			tar:            target.TestTcpTarget(t, conn, proj.GetPublicId(), "another populated", target.WithHostSets([]string{hs[0].GetPublicId()})),
			setHostSets:    []string{},
			resultHostSets: nil,
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

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test name")

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

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	removeCases := []struct {
		name        string
		tar         *target.TcpTarget
		removeHosts []string
		resultHosts []string
		wantErr     bool
	}{
		{
			name:        "Remove from empty",
			tar:         target.TestTcpTarget(t, conn, proj.GetPublicId(), "empty"),
			removeHosts: []string{hs[1].GetPublicId()},
			wantErr:     true,
		},
		{
			name:        "Remove 1 of 2 sets",
			tar:         target.TestTcpTarget(t, conn, proj.GetPublicId(), "remove partial", target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHosts: []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
		{
			name:        "Remove 1 duplicate set of 2 sets",
			tar:         target.TestTcpTarget(t, conn, proj.GetPublicId(), "remove duplicate", target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHosts: []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
		{
			name:        "Remove all hosts from set",
			tar:         target.TestTcpTarget(t, conn, proj.GetPublicId(), "remove all", target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()})),
			removeHosts: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{},
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

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "testing")

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

func TestAddTargetLibraries(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	store := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	cls := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)

	addCases := []struct {
		name             string
		tar              *target.TcpTarget
		addLibraryIds    []string
		addLibraries     []*pbs.CredentialLibrary
		resultLibraryIds []string
	}{
		{
			name:             "Add set on empty target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "empty"),
			addLibraryIds:    []string{cls[1].GetPublicId()},
			resultLibraryIds: []string{cls[1].GetPublicId()},
		},
		{
			name:             "Add library on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "populated", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			addLibraryIds:    []string{cls[1].GetPublicId()},
			resultLibraryIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
		},
		{
			name:             "Add duplicated libraries on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "duplicated", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			addLibraryIds:    []string{cls[1].GetPublicId(), cls[1].GetPublicId()},
			resultLibraryIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
		},
		{
			name:             "Add library on empty target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "empty for libraries"),
			addLibraries:     []*pbs.CredentialLibrary{{Id: cls[1].GetPublicId()}},
			resultLibraryIds: []string{cls[1].GetPublicId()},
		},
		{
			name:             "Add library on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "populated for libraries", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			addLibraries:     []*pbs.CredentialLibrary{{Id: cls[1].GetPublicId()}},
			resultLibraryIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
		},
		{
			name:             "Add duplicated libraries on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "duplicated for libraries", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			addLibraries:     []*pbs.CredentialLibrary{{Id: cls[1].GetPublicId()}, {Id: cls[1].GetPublicId()}},
			resultLibraryIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
		},
		{
			name:             "Add duplicated libraries across 2 fields on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "duplicated mixed", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			addLibraryIds:    []string{cls[1].GetPublicId()},
			addLibraries:     []*pbs.CredentialLibrary{{Id: cls[1].GetPublicId()}},
			resultLibraryIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.AddTargetCredentialLibrariesRequest{
				Id:                   tc.tar.GetPublicId(),
				Version:              tc.tar.GetVersion(),
				CredentialLibraryIds: tc.addLibraryIds,
				CredentialLibraries:  tc.addLibraries,
			}

			got, err := s.AddTargetCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultLibraryIds, got.GetItem().GetCredentialLibraryIds())

			assert.Equal(t, len(tc.resultLibraryIds), len(got.GetItem().GetCredentialLibraries()))

			wantTemplate := &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Purpose:           string(credential.ApplicationPurpose),
			}
			for _, cl := range got.GetItem().GetCredentialLibraries() {
				cl.Id = ""
				assert.Empty(t, cmp.Diff(wantTemplate, cl, protocmp.Transform()))
			}
		})
	}

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test")

	failCases := []struct {
		name string
		req  *pbs.AddTargetCredentialLibrariesRequest
		err  error
	}{
		{
			name: "Bad library Id",
			req: &pbs.AddTargetCredentialLibrariesRequest{
				Id:                   "bad id",
				Version:              tar.GetVersion(),
				CredentialLibraryIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.AddTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				Version:              tar.GetVersion() + 2,
				CredentialLibraryIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Empty library list",
			req: &pbs.AddTargetCredentialLibrariesRequest{
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect library ids",
			req: &pbs.AddTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				Version:              tar.GetVersion(),
				CredentialLibraryIds: []string{"incorrect"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect library id in libraries",
			req: &pbs.AddTargetCredentialLibrariesRequest{
				Id:                  tar.GetPublicId(),
				Version:             tar.GetVersion(),
				CredentialLibraries: []*pbs.CredentialLibrary{{Id: "incorrect"}},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect purpose in libraries",
			req: &pbs.AddTargetCredentialLibrariesRequest{
				Id:                  tar.GetPublicId(),
				Version:             tar.GetVersion(),
				CredentialLibraries: []*pbs.CredentialLibrary{{Id: cls[0].GetPublicId(), Purpose: "Wrong"}},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddTargetCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddTargetCredentialLibraries(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetTargetLibraries(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	store := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	cls := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)

	resultingTargetLibrary := func(id string) *pb.CredentialLibrary {
		return &pb.CredentialLibrary{
			Id:                id,
			CredentialStoreId: store.GetPublicId(),
			Purpose:           string(credential.ApplicationPurpose),
		}
	}

	setCases := []struct {
		name             string
		tar              *target.TcpTarget
		setLibraryIds    []string
		setLibraries     []*pbs.CredentialLibrary
		resultLibraryIds []string
		resultLibraries  []*pb.CredentialLibrary
	}{
		{
			name:             "Set on empty target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "empty"),
			setLibraryIds:    []string{cls[1].GetPublicId()},
			resultLibraryIds: []string{cls[1].GetPublicId()},
		},
		{
			name:             "Set on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "populated", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			setLibraryIds:    []string{cls[1].GetPublicId()},
			resultLibraryIds: []string{cls[1].GetPublicId()},
		},
		{
			name:             "Set duplicate libraries on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "duplicate", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			setLibraryIds:    []string{cls[1].GetPublicId(), cls[1].GetPublicId()},
			resultLibraryIds: []string{cls[1].GetPublicId()},
		},
		{
			name:             "Set duplicate libraries on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "duplicate with libraries", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			setLibraryIds:    []string{cls[1].GetPublicId()},
			setLibraries:     []*pbs.CredentialLibrary{{Id: cls[1].GetPublicId()}},
			resultLibraryIds: []string{cls[1].GetPublicId()},
		},
		{
			name:             "Set across libraries and library",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "across fields"),
			setLibraryIds:    []string{cls[0].GetPublicId()},
			setLibraries:     []*pbs.CredentialLibrary{{Id: cls[1].GetPublicId()}},
			resultLibraryIds: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
			resultLibraries:  []*pb.CredentialLibrary{resultingTargetLibrary(cls[0].GetPublicId()), resultingTargetLibrary(cls[1].GetPublicId())},
		},
		{
			name:             "Set empty on populated target",
			tar:              target.TestTcpTarget(t, conn, proj.GetPublicId(), "another populated", target.WithCredentialLibraries([]string{cls[0].GetPublicId()})),
			setLibraryIds:    []string{},
			resultLibraryIds: nil,
		},
	}
	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.SetTargetCredentialLibrariesRequest{
				Id:                   tc.tar.GetPublicId(),
				Version:              tc.tar.GetVersion(),
				CredentialLibraryIds: tc.setLibraryIds,
				CredentialLibraries:  tc.setLibraries,
			}

			got, err := s.SetTargetCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.NoError(t, err, "Got error: %v", s)
			assert.ElementsMatch(t, tc.resultLibraryIds, got.GetItem().GetCredentialLibraryIds())

			if len(tc.resultLibraries) != 0 {
				sort.Slice(tc.resultLibraries, func(i, j int) bool {
					return tc.resultLibraries[i].GetId() < tc.resultLibraries[j].GetId()
				})
				sort.Slice(got.GetItem().CredentialLibraries, func(i, j int) bool {
					return got.GetItem().CredentialLibraries[i].GetId() < got.GetItem().CredentialLibraries[j].GetId()
				})
				assert.Empty(t, cmp.Diff(tc.resultLibraries, got.GetItem().GetCredentialLibraries(), protocmp.Transform()))
			} else {
				assert.Equal(t, len(tc.resultLibraryIds), len(got.GetItem().GetCredentialLibraries()))
				for _, cl := range got.GetItem().GetCredentialLibraries() {
					assert.Empty(t, cmp.Diff(resultingTargetLibrary(cl.Id), cl, protocmp.Transform()))
				}
			}
		})
	}

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test name")

	failCases := []struct {
		name string
		req  *pbs.SetTargetCredentialLibrariesRequest
		err  error
	}{
		{
			name: "Bad target Id",
			req: &pbs.SetTargetCredentialLibrariesRequest{
				Id:                   "bad id",
				Version:              tar.GetVersion(),
				CredentialLibraryIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad version",
			req: &pbs.SetTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				Version:              tar.GetVersion() + 3,
				CredentialLibraryIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad library id",
			req: &pbs.SetTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				Version:              tar.GetVersion(),
				CredentialLibraryIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect library id in libraries",
			req: &pbs.SetTargetCredentialLibrariesRequest{
				Id:                  tar.GetPublicId(),
				Version:             tar.GetVersion(),
				CredentialLibraries: []*pbs.CredentialLibrary{{Id: "incorrect"}},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Incorrect purpose in libraries",
			req: &pbs.SetTargetCredentialLibrariesRequest{
				Id:                  tar.GetPublicId(),
				Version:             tar.GetVersion(),
				CredentialLibraries: []*pbs.CredentialLibrary{{Id: cls[0].GetPublicId(), Purpose: "Wrong"}},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetTargetCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetTargetCredentialLibraries(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveTargetLibraries(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(t, err, "Error when getting new target service.")

	store := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	cls := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)

	removeCases := []struct {
		name       string
		tar        *target.TcpTarget
		removeLibs []string
		resultLibs []string
		wantErr    bool
	}{
		{
			name:       "Remove from empty",
			tar:        target.TestTcpTarget(t, conn, proj.GetPublicId(), "empty"),
			removeLibs: []string{cls[1].GetPublicId()},
			wantErr:    true,
		},
		{
			name:       "Remove 1 of 2 libraries",
			tar:        target.TestTcpTarget(t, conn, proj.GetPublicId(), "remove partial", target.WithCredentialLibraries([]string{cls[0].GetPublicId(), cls[1].GetPublicId()})),
			removeLibs: []string{cls[1].GetPublicId()},
			resultLibs: []string{cls[0].GetPublicId()},
		},
		{
			name:       "Remove 1 duplicate set of 2 libraries",
			tar:        target.TestTcpTarget(t, conn, proj.GetPublicId(), "remove duplicate", target.WithCredentialLibraries([]string{cls[0].GetPublicId(), cls[1].GetPublicId()})),
			removeLibs: []string{cls[1].GetPublicId(), cls[1].GetPublicId()},
			resultLibs: []string{cls[0].GetPublicId()},
		},
		{
			name:       "Remove all libraries from target",
			tar:        target.TestTcpTarget(t, conn, proj.GetPublicId(), "remove all", target.WithCredentialLibraries([]string{cls[0].GetPublicId(), cls[1].GetPublicId()})),
			removeLibs: []string{cls[0].GetPublicId(), cls[1].GetPublicId()},
			resultLibs: []string{},
		},
	}

	for _, tc := range removeCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.RemoveTargetCredentialLibrariesRequest{
				Id:                   tc.tar.GetPublicId(),
				Version:              tc.tar.GetVersion(),
				CredentialLibraryIds: tc.removeLibs,
			}

			got, err := s.RemoveTargetCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultLibs, got.GetItem().GetCredentialLibraryIds())
		})
	}

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "testing")

	failCases := []struct {
		name string
		req  *pbs.RemoveTargetCredentialLibrariesRequest
		err  error
	}{
		{
			name: "Bad version",
			req: &pbs.RemoveTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				Version:              tar.GetVersion() + 3,
				CredentialLibraryIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad target Id",
			req: &pbs.RemoveTargetCredentialLibrariesRequest{
				Id:                   "bad id",
				Version:              tar.GetVersion(),
				CredentialLibraryIds: []string{cls[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "empty libraries",
			req: &pbs.RemoveTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				Version:              tar.GetVersion(),
				CredentialLibraryIds: []string{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid library ids",
			req: &pbs.RemoveTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				Version:              tar.GetVersion(),
				CredentialLibraryIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveTargetCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveTargetCredentialLibraries(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestAuthorizeSession(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	staticHostRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	credentialRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}

	org, proj := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	ctx := auth.NewVerifierContext(requests.NewRequestContext(context.Background()),
		nil,
		iamRepoFn,
		atRepoFn,
		serversRepoFn,
		kms,
		auth.RequestInfo{
			Token:       at.GetToken(),
			TokenFormat: auth.AuthTokenTypeBearer,
			PublicId:    at.GetPublicId(),
		})

	r := iam.TestRole(t, conn, proj.GetPublicId())
	_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
	_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), "id=*;type=*;actions=*")

	s, err := targets.NewService(kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, staticHostRepoFn, credentialRepoFn)
	require.NoError(t, err)

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test")
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	_ = static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	apiTar, err := s.AddTargetHostSets(ctx, &pbs.AddTargetHostSetsRequest{
		Id:         tar.GetPublicId(),
		Version:    tar.GetVersion(),
		HostSetIds: []string{hs.GetPublicId()},
	})
	require.NoError(t, err)

	// Tell our DB that there is a worker ready to serve the data
	workerService := workers.NewWorkerServiceServer(hclog.Default(), serversRepoFn, sessionRepoFn, &sync.Map{}, kms)
	_, err = workerService.Status(ctx, &spbs.StatusRequest{
		Worker: &spb.Server{
			PrivateId: "testworker",
			Address:   "localhost:8457",
		},
	})
	require.NoError(t, err)

	v := vault.NewTestVaultServer(t)
	v.MountPKI(t)
	sec, tok := v.CreateToken(t, vault.WithPolicies([]string{"default", "boundary-controller", "pki"}))

	store := vault.TestCredentialStore(t, conn, wrapper, proj.GetPublicId(), v.Addr, tok, sec.Auth.Accessor)
	credService, err := credentiallibraries.NewService(credentialRepoFn, iamRepoFn)
	require.NoError(t, err)
	clsResp, err := credService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credpb.CredentialLibrary{
		CredentialStoreId: store.GetPublicId(),
		Name:              wrapperspb.String("Library Name"),
		Description:       wrapperspb.String("Library Description"),
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"path":              structpb.NewStringValue(path.Join("pki", "issue", "boundary")),
			"http_method":       structpb.NewStringValue("POST"),
			"http_request_body": structpb.NewStringValue(`{"common_name":"boundary.com"}`),
		}},
	}})
	require.NoError(t, err)

	_, err = s.AddTargetCredentialLibraries(ctx,
		&pbs.AddTargetCredentialLibrariesRequest{
			Id:                   tar.GetPublicId(),
			CredentialLibraryIds: []string{clsResp.GetItem().GetId()},
			Version:              apiTar.GetItem().GetVersion(),
		})
	require.NoError(t, err)

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
		HostSetId: hs.GetPublicId(),
		HostId:    h.GetPublicId(),
		Type:      "tcp",
		Endpoint:  fmt.Sprintf("tcp://%s", h.GetAddress()),
		Credentials: []*pb.SessionCredential{{
			CredentialLibrary: &pb.CredentialLibrary{
				Id:                clsResp.GetItem().GetId(),
				Name:              clsResp.GetItem().GetName().GetValue(),
				Description:       clsResp.GetItem().GetDescription().GetValue(),
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.VaultSubtype.String(),
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
	_ = wantSecret
	got := asRes1.GetItem()

	require.Len(t, got.GetCredentials(), 1)

	gotCred := got.Credentials[0]
	assert.NotEmpty(t, gotCred.Secret)
	dSec := decodeJsonSecret(t, gotCred.Secret)
	require.NoError(t, err)
	for k, v := range wantSecret {
		gotV, ok := dSec[k]
		require.True(t, ok)
		assert.Truef(t, strings.HasPrefix(gotV.(string), v.(string)), "%q:%q doesn't have prefix %q", k, gotV, v)
	}
	gotCred.Secret = ""

	got.AuthorizationToken, got.SessionId, got.CreatedTime = "", "", nil
	assert.Empty(t, cmp.Diff(got, want, protocmp.Transform()))
}

func TestAuthorizeSession_Errors(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	staticHostRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	credentialRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	org, proj := iam.TestScopes(t, iamRepo)

	s, err := targets.NewService(kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, staticHostRepoFn, credentialRepoFn)
	require.NoError(t, err)

	// Authorized user gets full permissions
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	ctx := auth.NewVerifierContext(requests.NewRequestContext(context.Background()),
		nil,
		iamRepoFn,
		atRepoFn,
		serversRepoFn,
		kms,
		auth.RequestInfo{
			Token:       at.GetToken(),
			TokenFormat: auth.AuthTokenTypeBearer,
			PublicId:    at.GetPublicId(),
		})
	r := iam.TestRole(t, conn, proj.GetPublicId())
	_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
	_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), "id=*;type=*;actions=*")

	v := vault.NewTestVaultServer(t, vault.WithDockerNetwork(true))
	v.MountDatabase(t)
	sec, tok := v.CreateToken(t, vault.WithPolicies([]string{"default", "database"}))
	store := vault.TestCredentialStore(t, conn, wrapper, proj.GetPublicId(), v.Addr, tok, sec.Auth.Accessor)

	workerExists := func(tar *target.TcpTarget) (version uint32) {
		workerService := workers.NewWorkerServiceServer(hclog.Default(), serversRepoFn, sessionRepoFn, &sync.Map{}, kms)
		_, err := workerService.Status(context.Background(), &spbs.StatusRequest{
			Worker: &spb.Server{
				PrivateId: "testworker",
				Address:   "localhost:123",
			},
		})
		require.NoError(t, err)
		return tar.GetVersion()
	}

	hostSetNoHostExists := func(tar *target.TcpTarget) (version uint32) {
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

		tr, err := s.AddTargetHostSets(ctx, &pbs.AddTargetHostSetsRequest{
			Id:         tar.GetPublicId(),
			Version:    tar.GetVersion(),
			HostSetIds: []string{hs.GetPublicId()},
		})
		require.NoError(t, err)
		return tr.GetItem().GetVersion()
	}

	hostExists := func(tar *target.TcpTarget) (version uint32) {
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		_ = static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		apiTar, err := s.AddTargetHostSets(ctx, &pbs.AddTargetHostSetsRequest{
			Id:         tar.GetPublicId(),
			Version:    tar.GetVersion(),
			HostSetIds: []string{hs.GetPublicId()},
		})
		require.NoError(t, err)
		return apiTar.GetItem().GetVersion()
	}

	libraryExists := func(tar *target.TcpTarget) (version uint32) {
		credService, err := credentiallibraries.NewService(credentialRepoFn, iamRepoFn)
		require.NoError(t, err)
		clsResp, err := credService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credpb.CredentialLibrary{
			CredentialStoreId: store.GetPublicId(),
			Description:       wrapperspb.String(fmt.Sprintf("Library Description for target %q", tar.GetName())),
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"path": structpb.NewStringValue(path.Join("database", "creds", "opened")),
			}},
		}})
		require.NoError(t, err)

		tr, err := s.AddTargetCredentialLibraries(ctx,
			&pbs.AddTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				CredentialLibraryIds: []string{clsResp.GetItem().GetId()},
				Version:              tar.GetVersion(),
			})
		require.NoError(t, err)
		return tr.GetItem().GetVersion()
	}

	misConfiguredlibraryExists := func(tar *target.TcpTarget) (version uint32) {
		credService, err := credentiallibraries.NewService(credentialRepoFn, iamRepoFn)
		require.NoError(t, err)
		clsResp, err := credService.CreateCredentialLibrary(ctx, &pbs.CreateCredentialLibraryRequest{Item: &credpb.CredentialLibrary{
			CredentialStoreId: store.GetPublicId(),
			Description:       wrapperspb.String(fmt.Sprintf("Library Description for target %q", tar.GetName())),
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"path": structpb.NewStringValue("bad path"),
			}},
		}})
		require.NoError(t, err)

		tr, err := s.AddTargetCredentialLibraries(ctx,
			&pbs.AddTargetCredentialLibrariesRequest{
				Id:                   tar.GetPublicId(),
				CredentialLibraryIds: []string{clsResp.GetItem().GetId()},
				Version:              tar.GetVersion(),
			})
		require.NoError(t, err)
		return tr.GetItem().GetVersion()
	}

	cases := []struct {
		name  string
		setup []func(*target.TcpTarget) uint32
		err   bool
	}{
		{
			// This one must be run first since it relies on the DB not having any worker details
			name:  "no worker",
			setup: []func(tcpTarget *target.TcpTarget) uint32{hostExists, libraryExists},
			err:   true,
		},
		{
			name:  "success",
			setup: []func(tcpTarget *target.TcpTarget) uint32{workerExists, hostExists, libraryExists},
		},
		{
			name:  "no hosts",
			setup: []func(tcpTarget *target.TcpTarget) uint32{workerExists, hostSetNoHostExists, libraryExists},
			err:   true,
		},
		{
			name:  "bad library configuration",
			setup: []func(tcpTarget *target.TcpTarget) uint32{workerExists, hostExists, misConfiguredlibraryExists},
			err:   true,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), fmt.Sprintf("test-%d", i))

			for _, fn := range tc.setup {
				ver := fn(tar)
				tar.Version = ver
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
	dec.UseNumber()
	require.NoError(t, dec.Decode(&ret))
	return ret
}
