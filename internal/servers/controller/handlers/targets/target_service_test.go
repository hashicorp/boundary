package targets_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
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
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func testService(t *testing.T, conn *gorm.DB, kms *kms.Kms, wrapper wrapping.Wrapper) (targets.Service, error) {
	rw := db.New(conn)
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
	return targets.NewService(kms, repoFn, iamRepoFn, serversRepoFn, sessionRepoFn, staticHostRepoFn)
}

func TestGet(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test", target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()}))

	pTar := &pb.Target{
		Id:                     tar.GetPublicId(),
		ScopeId:                proj.GetPublicId(),
		Name:                   wrapperspb.String("test"),
		CreatedTime:            tar.CreateTime.GetTimestamp(),
		UpdatedTime:            tar.UpdateTime.GetTimestamp(),
		Scope:                  &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		Type:                   target.TcpTargetType.String(),
		HostSetIds:             []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		Attributes:             new(structpb.Struct),
		SessionMaxSeconds:      wrapperspb.UInt32(28800),
		SessionConnectionLimit: wrapperspb.Int32(1),
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

			got, gErr := s.GetTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
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

	_, projNoTar := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hss := static.TestSets(t, conn, hc.GetPublicId(), 2)

	var wantTars []*pb.Target
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("tar%d", i)
		tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), name, target.WithHostSets([]string{hss[0].GetPublicId(), hss[1].GetPublicId()}))
		wantTars = append(wantTars, &pb.Target{
			Id:                     tar.GetPublicId(),
			ScopeId:                proj.GetPublicId(),
			Name:                   wrapperspb.String(name),
			Scope:                  &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
			CreatedTime:            tar.GetCreateTime().GetTimestamp(),
			UpdatedTime:            tar.GetUpdateTime().GetTimestamp(),
			Version:                tar.GetVersion(),
			Type:                   target.TcpTargetType.String(),
			Attributes:             new(structpb.Struct),
			SessionMaxSeconds:      wrapperspb.UInt32(28800),
			SessionConnectionLimit: wrapperspb.Int32(1),
		})
	}

	cases := []struct {
		name    string
		scopeId string
		res     *pbs.ListTargetsResponse
		err     error
	}{
		{
			name:    "List Many Host Sets",
			scopeId: proj.GetPublicId(),
			res:     &pbs.ListTargetsResponse{Items: wantTars},
		},
		{
			name:    "List No Host Sets",
			scopeId: projNoTar.GetPublicId(),
			res:     &pbs.ListTargetsResponse{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := testService(t, conn, kms, wrapper)
			require.NoError(err, "Couldn't create new host set service.")

			got, gErr := s.ListTargets(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), &pbs.ListTargetsRequest{ScopeId: tc.scopeId})
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListTargets(%q) got error %v, wanted %v", tc.scopeId, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListTargets(%q) got response %q, wanted %q", tc.scopeId, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
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
			res: &pbs.DeleteTargetResponse{},
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
			got, gErr := s.DeleteTarget(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
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

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test")

	s, err := testService(t, conn, kms, wrapper)
	require.NoError(err, "Couldn't create a new target service.")
	req := &pbs.DeleteTargetRequest{
		Id: tar.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId()))
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

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

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
			}},
			res: &pbs.CreateTargetResponse{
				Uri: fmt.Sprintf("targets/%s_", target.TcpTargetPrefix),
				Item: &pb.Target{
					ScopeId:     proj.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        wrapperspb.String("name"),
					Description: wrapperspb.String("desc"),
					Type:        target.TcpTargetType.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"default_port": structpb.NewNumberValue(2),
					}},
					SessionMaxSeconds:      wrapperspb.UInt32(28800),
					SessionConnectionLimit: wrapperspb.Int32(1),
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
				CreatedTime: ptypes.TimestampNow(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				UpdatedTime: ptypes.TimestampNow(),
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

			got, gErr := s.CreateTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateTarget(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateTarget(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

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
	gtar, _, err := repo.CreateTcpTarget(context.Background(), tar, target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()}))
	require.NoError(t, err)
	tar = gtar.(*target.TcpTarget)

	var version uint32 = 1

	resetTarget := func() {
		version++
		_, _, _, err = repo.UpdateTcpTarget(context.Background(), tar, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset target.")
		version++
	}

	hCreated, err := ptypes.Timestamp(tar.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Failed to convert proto to timestamp")
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
					Type: target.TcpSubType.String(),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
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
					Type: target.TcpSubType.String(),
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					ScopeId:     tar.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
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
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
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
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
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
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
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
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
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
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        wrapperspb.String("new"),
					Description: wrapperspb.String("new desc"),
				}},
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
					CreatedTime: ptypes.TimestampNow(),
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
					UpdatedTime: ptypes.TimestampNow(),
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

			got, gErr := tested.UpdateTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateTarget(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetTarget()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHost response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Failed to convert proto to timestamp")
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

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new target repo.")

	tar, err := target.NewTcpTarget(proj.GetPublicId(), target.WithName("default"), target.WithDescription("default"))
	tar.DefaultPort = 2
	require.NoError(t, err)
	gtar, _, err := repo.CreateTcpTarget(context.Background(), tar)
	require.NoError(t, err)

	tested, err := testService(t, conn, kms, wrapper)
	require.NoError(t, err, "Failed to create a new host set service.")

	upTar, err := tested.UpdateTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), &pbs.UpdateTargetRequest{
		Id:         gtar.GetPublicId(),
		Item:       &pb.Target{
			Description:            wrapperspb.String("updated"),
			Version:                72,
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

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

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

			got, err := s.AddTargetHostSets(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
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
				Id:      tar.GetPublicId(),
				Version: tar.GetVersion(),
				HostSetIds: []string{"incorrect"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddTargetHostSets(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
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

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

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

			got, err := s.SetTargetHostSets(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
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
			_, gErr := s.SetTargetHostSets(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
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

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

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

			got, err := s.RemoveTargetHostSets(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
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
			_, gErr := s.RemoveTargetHostSets(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveTargetHostSets(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}
