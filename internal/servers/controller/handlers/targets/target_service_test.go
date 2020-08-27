package targets_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGet(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 2)

	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test", target.WithHostSets([]string{hs[0].GetPublicId(), hs[1].GetPublicId()}))

	pTar := &pb.Target{
		Id:          tar.GetPublicId(),
		Name:        wrapperspb.String("test"),
		CreatedTime: tar.CreateTime.GetTimestamp(),
		UpdatedTime: tar.UpdateTime.GetTimestamp(),
		Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		Type:        target.TcpTargetType.String(),
		HostSetIds:  []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
	}
	for _, ihs := range hs {
		pTar.HostSets = append(pTar.HostSets, &pb.HostSet{Id: ihs.GetPublicId(), HostCatalogId: ihs.GetCatalogId()})
	}

	cases := []struct {
		name    string
		req     *pbs.GetTargetRequest
		res     *pbs.GetTargetResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Target",
			req:     &pbs.GetTargetRequest{Id: tar.GetPublicId()},
			res:     &pbs.GetTargetResponse{Item: pTar},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing Target",
			req:     &pbs.GetTargetRequest{Id: target.TcpTargetPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetTargetRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetTargetRequest{Id: target.TcpTargetPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)

			s, err := targets.NewService(repoFn)
			require.NoError(t, err, "Couldn't create a new host set service.")

			got, gErr := s.GetTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetTarget(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)

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

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	_, projNoTar := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hss := static.TestSets(t, conn, hc.GetPublicId(), 2)

	var wantTars []*pb.Target
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("tar%d", i)
		tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), name, target.WithHostSets([]string{hss[0].GetPublicId(), hss[1].GetPublicId()}))
		wantTars = append(wantTars, &pb.Target{
			Id:          tar.GetPublicId(),
			Name:        wrapperspb.String(name),
			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
			CreatedTime: tar.GetCreateTime().GetTimestamp(),
			UpdatedTime: tar.GetUpdateTime().GetTimestamp(),
			Version:     tar.GetVersion(),
			Type:        target.TcpTargetType.String(),
		})
	}

	cases := []struct {
		name    string
		scopeId string
		res     *pbs.ListTargetsResponse
		errCode codes.Code
	}{
		{
			name:    "List Many Host Sets",
			scopeId: proj.GetPublicId(),
			res:     &pbs.ListTargetsResponse{Items: wantTars},
			errCode: codes.OK,
		},
		{
			name:    "List No Host Sets",
			scopeId: projNoTar.GetPublicId(),
			res:     &pbs.ListTargetsResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := targets.NewService(repoFn)
			require.NoError(err, "Couldn't create new host set service.")

			got, gErr := s.ListTargets(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), &pbs.ListTargetsRequest{})
			assert.Equal(tc.errCode, status.Code(gErr), "ListTargets(%q) got error %v, wanted %v", tc.scopeId, gErr, tc.errCode)
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

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}

	s, err := targets.NewService(repoFn)
	require.NoError(t, err, "Couldn't create a new target service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteTargetRequest
		res     *pbs.DeleteTargetResponse
		errCode codes.Code
	}{
		{
			name:    "Delete an Existing Target",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteTargetRequest{
				Id: tar.GetPublicId(),
			},
			res: &pbs.DeleteTargetResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete Not Existing Target",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteTargetRequest{
				Id: target.TcpTargetPrefix + "_doesntexis",
			},
			res: &pbs.DeleteTargetResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Bad target id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteTargetRequest{
				Id: target.TcpTargetPrefix + "_bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteTarget(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteTarget(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "DeleteTarget(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}
	tar := target.TestTcpTarget(t, conn, proj.GetPublicId(), "test")

	s, err := targets.NewService(repoFn)
	require.NoError(t, err, "Couldn't create a new target service.")
	req := &pbs.DeleteTargetRequest{
		Id: tar.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId()))
	got, gErr := s.DeleteTarget(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteTarget(ctx, req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(rw, rw, kms)
	}

	cases := []struct {
		name    string
		req     *pbs.CreateTargetRequest
		res     *pbs.CreateTargetResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid target",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        target.TcpTargetType.String(),
			}},
			res: &pbs.CreateTargetResponse{
				Uri: fmt.Sprintf("scopes/%s/targets/%s_", proj.GetPublicId(), target.TcpTargetPrefix),
				Item: &pb.Target{
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "name"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        target.TcpTargetType.String(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "ThisIsMadeUp",
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create with no type",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Name:        &wrappers.StringValue{Value: "no type name"},
				Description: &wrappers.StringValue{Value: "no type desc"},
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateTargetRequest{Item: &pb.Target{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := targets.NewService(repoFn)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateTarget(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
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

	tested, err := targets.NewService(repoFn)
	require.NoError(t, err, "Failed to create a new host set service.")

	cases := []struct {
		name    string
		req     *pbs.UpdateTargetRequest
		res     *pbs.UpdateTargetResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing Target",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        target.TcpTargetType.String(),
					HostSetIds:  hsIds,
					HostSets:    hostSets,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        target.TcpTargetType.String(),
					HostSetIds:  hsIds,
					HostSets:    hostSets,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateTargetRequest{
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Target{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Target{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "default"},
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        target.TcpTargetType.String(),
					HostSetIds:  hsIds,
					HostSets:    hostSets,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "default"},
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        target.TcpTargetType.String(),
					HostSetIds:  hsIds,
					HostSets:    hostSets,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateTargetResponse{
				Item: &pb.Target{
					Id:          tar.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "default"},
					Description: &wrappers.StringValue{Value: "notignored"},
					CreatedTime: tar.GetCreateTime().GetTimestamp(),
					Type:        target.TcpTargetType.String(),
					HostSetIds:  hsIds,
					HostSets:    hostSets,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update a Non Existing Host Set",
			req: &pbs.UpdateTargetRequest{
				Id: target.TcpTargetPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Target{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
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
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
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
			res:     nil,
			errCode: codes.InvalidArgument,
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
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateTargetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Target{
					Type: "Unknown",
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tc.req.Item.Version = version

			req := proto.Clone(toMerge).(*pbs.UpdateTargetRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Item.Version = version + 2
			_, gErr := tested.UpdateTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateTarget(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateTarget(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.errCode == codes.OK {
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
