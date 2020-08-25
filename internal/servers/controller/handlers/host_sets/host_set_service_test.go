package host_sets_test

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
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestGet(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	h := static.TestHosts(t, conn, hc.GetPublicId(), 2)
	static.TestSetMembers(t, conn, hs.GetPublicId(), h)
	hIds := []string{h[0].GetPublicId(), h[1].GetPublicId()}

	toMerge := &pbs.GetHostSetRequest{
		HostCatalogId: hc.GetPublicId(),
	}

	pHost := &pb.HostSet{
		HostCatalogId: hc.GetPublicId(),
		Id:            hs.GetPublicId(),
		CreatedTime:   hs.CreateTime.GetTimestamp(),
		UpdatedTime:   hs.UpdateTime.GetTimestamp(),
		Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		Type:          "static",
		HostIds:       hIds,
	}

	cases := []struct {
		name    string
		req     *pbs.GetHostSetRequest
		res     *pbs.GetHostSetResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Host",
			req:     &pbs.GetHostSetRequest{Id: hs.GetPublicId()},
			res:     &pbs.GetHostSetResponse{Item: pHost},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing Host Set",
			req:     &pbs.GetHostSetRequest{Id: static.HostSetPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetHostSetRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetHostSetRequest{Id: static.HostPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(repoFn)
			require.NoError(t, err, "Couldn't create a new host set service.")

			got, gErr := s.GetHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 2)
	hc, hcNoHosts := hcs[0], hcs[1]

	var wantHs []*pb.HostSet
	for _, h := range static.TestSets(t, conn, hc.GetPublicId(), 10) {
		wantHs = append(wantHs, &pb.HostSet{
			Id:            h.GetPublicId(),
			HostCatalogId: h.GetCatalogId(),
			Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
			CreatedTime:   h.GetCreateTime().GetTimestamp(),
			UpdatedTime:   h.GetUpdateTime().GetTimestamp(),
			Version:       h.GetVersion(),
			Type:          host.StaticSubtype.String(),
		})
	}

	cases := []struct {
		name          string
		hostCatalogId string
		res           *pbs.ListHostSetsResponse
		errCode       codes.Code
	}{
		{
			name:          "List Many Host Sets",
			hostCatalogId: hc.GetPublicId(),
			res:           &pbs.ListHostSetsResponse{Items: wantHs},
			errCode:       codes.OK,
		},
		{
			name:          "List No Host Sets",
			hostCatalogId: hcNoHosts.GetPublicId(),
			res:           &pbs.ListHostSetsResponse{},
			errCode:       codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := host_sets.NewService(repoFn)
			require.NoError(err, "Couldn't create new host set service.")

			got, gErr := s.ListHostSets(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), &pbs.ListHostSetsRequest{HostCatalogId: tc.hostCatalogId})
			assert.Equal(tc.errCode, status.Code(gErr), "ListHostSets(%q) got error %v, wanted %v", tc.hostCatalogId, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHostSets(%q) got response %q, wanted %q", tc.hostCatalogId, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	s, err := host_sets.NewService(repoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteHostSetRequest
		res     *pbs.DeleteHostSetResponse
		errCode codes.Code
	}{
		{
			name:    "Delete an Existing Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            h.GetPublicId(),
			},
			res: &pbs.DeleteHostSetResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad id Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            static.HostSetPrefix + "_doesntexis",
			},
			res: &pbs.DeleteHostSetResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad host catalog id in Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				HostCatalogId: static.HostCatalogPrefix + "_doesntexis",
				Id:            h.GetPublicId(),
			},
			res: &pbs.DeleteHostSetResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Bad Host Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            static.HostSetPrefix + "_bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "DeleteHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	s, err := host_sets.NewService(repoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")
	req := &pbs.DeleteHostSetRequest{
		HostCatalogId: hc.GetPublicId(),
		Id:            h.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId()))
	got, gErr := s.DeleteHostSet(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteHostSet(ctx, req)
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	toMerge := &pbs.CreateHostSetRequest{
		HostCatalogId: hc.GetPublicId(),
	}

	defaultHcCreated, err := ptypes.Timestamp(hc.GetCreateTime().GetTimestamp())
	require.NoError(t, err)

	cases := []struct {
		name    string
		req     *pbs.CreateHostSetRequest
		res     *pbs.CreateHostSetResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid Host",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "static",
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("scopes/%s/host-catalogs/%s/host-sets/%s_", proj.GetPublicId(), hc.GetPublicId(), static.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "name"},
					Description:   &wrappers.StringValue{Value: "desc"},
					Type:          "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "ThisIsMadeUp",
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				Name:        &wrappers.StringValue{Value: "no type name"},
				Description: &wrappers.StringValue{Value: "no type desc"},
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("scopes/%s/host-catalogs/%s/host-sets/%s_", proj.GetPublicId(), hc.GetPublicId(), static.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "no type name"},
					Description:   &wrappers.StringValue{Value: "no type desc"},
					Type:          "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(repoFn)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostSetPrefix), got.GetItem().GetId())
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a set created after the test setup's default set
				assert.True(gotCreateTime.After(defaultHcCreated), "New set should have been created after default set. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New set should have been updated after default set. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHostSet(%q) got response %q, wanted %q", req, got, tc.res)
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new static repo.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	h := static.TestHosts(t, conn, hc.GetPublicId(), 2)
	hIds := []string{h[0].GetPublicId(), h[1].GetPublicId()}

	hs, err := static.NewHostSet(hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
	require.NoError(t, err)
	hs, err = repo.CreateSet(context.Background(), proj.GetPublicId(), hs)
	require.NoError(t, err)

	static.TestSetMembers(t, conn, hs.GetPublicId(), h)

	var version uint32 = 1

	resetHostSet := func() {
		version++
		_, _, _, err = repo.UpdateSet(context.Background(), proj.GetPublicId(), hs, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset host.")
		version++
	}

	hCreated, err := ptypes.Timestamp(hs.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Failed to convert proto to timestamp")
	toMerge := &pbs.UpdateHostSetRequest{
		HostCatalogId: hc.GetPublicId(),
		Id:            hs.GetPublicId(),
	}

	tested, err := host_sets.NewService(repoFn)
	require.NoError(t, err, "Failed to create a new host set service.")

	cases := []struct {
		name    string
		req     *pbs.UpdateHostSetRequest
		res     *pbs.UpdateHostSetResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing Host",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Id:            hs.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "new"},
					Description:   &wrappers.StringValue{Value: "desc"},
					CreatedTime:   hs.GetCreateTime().GetTimestamp(),
					Type:          "static",
					HostIds:       hIds,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Id:            hs.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "new"},
					Description:   &wrappers.StringValue{Value: "desc"},
					CreatedTime:   hs.GetCreateTime().GetTimestamp(),
					Type:          "static",
					HostIds:       hIds,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostSetRequest{
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostSet{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Id:            hs.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Description:   &wrappers.StringValue{Value: "default"},
					CreatedTime:   hs.GetCreateTime().GetTimestamp(),
					Type:          "static",
					HostIds:       hIds,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostSet{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Id:            hs.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "default"},
					CreatedTime:   hs.GetCreateTime().GetTimestamp(),
					Type:          "static",
					HostIds:       hIds,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Id:            hs.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "updated"},
					Description:   &wrappers.StringValue{Value: "default"},
					CreatedTime:   hs.GetCreateTime().GetTimestamp(),
					Type:          "static",
					HostIds:       hIds,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Id:            hs.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "default"},
					Description:   &wrappers.StringValue{Value: "notignored"},
					CreatedTime:   hs.GetCreateTime().GetTimestamp(),
					Type:          "static",
					HostIds:       hIds,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update a Non Existing Host Set",
			req: &pbs.UpdateHostSetRequest{
				Id: static.HostSetPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostSetRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.HostSet{
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
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.HostSet{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.HostSet{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostSet{
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

			req := proto.Clone(toMerge).(*pbs.UpdateHostSetRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Item.Version = version + 2
			_, gErr := tested.UpdateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.errCode == codes.OK {
				defer resetHostSet()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHost response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Failed to convert proto to timestamp")
				// Verify it is a set updated after it was created
				// TODO: This is currently failing.
				assert.True(gotUpdateTime.After(hCreated), "Updated set should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, hCreated)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = version + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestAddHostSetHosts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	s, err := host_sets.NewService(repoFn)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestHosts(t, conn, hc.GetPublicId(), 4)

	addCases := []struct {
		name        string
		setup       func(*static.HostSet)
		addHosts    []string
		resultHosts []string
	}{
		{
			name:        "Add host on empty set",
			setup:       func(g *static.HostSet) {},
			addHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[1].GetPublicId()},
		},
		{
			name: "Add host on populated set",
			setup: func(g *static.HostSet) {
				static.TestSetMembers(t, conn, g.GetPublicId(), hs[:1])
			},
			addHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
			tc.setup(ss)
			req := &pbs.AddHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            ss.GetPublicId(),
				Version:       ss.GetVersion(),
				HostIds:       tc.addHosts,
			}

			got, err := s.AddHostSetHosts(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHosts, got.GetItem().GetHostIds())
		})
	}

	ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	failCases := []struct {
		name    string
		req     *pbs.AddHostSetHostsRequest
		errCode codes.Code
	}{
		{
			name: "Bad Set Id",
			req: &pbs.AddHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            "bad id",
				Version:       ss.GetVersion(),
				HostIds:       []string{hs[0].GetPublicId()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Catalog Id",
			req: &pbs.AddHostSetHostsRequest{
				HostCatalogId: "bad catalog id",
				Id:            ss.GetPublicId(),
				Version:       ss.GetVersion(),
				HostIds:       []string{hs[0].GetPublicId()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Empty host list",
			req: &pbs.AddHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            ss.GetPublicId(),
				Version:       ss.GetVersion(),
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.AddHostSetHosts(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "AddHostSetHosts(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestSetHostSetHosts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	s, err := host_sets.NewService(repoFn)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestHosts(t, conn, hc.GetPublicId(), 4)

	setCases := []struct {
		name        string
		setup       func(*static.HostSet)
		setHosts    []string
		resultHosts []string
	}{
		{
			name:        "Set host on empty set",
			setup:       func(r *static.HostSet) {},
			setHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[1].GetPublicId()},
		},
		{
			name: "Set host on populated set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:1])
			},
			setHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[1].GetPublicId()},
		},
		{
			name: "Set empty on populated set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:2])
			},
			setHosts:    []string{},
			resultHosts: nil,
		},
	}
	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
			tc.setup(ss)
			req := &pbs.SetHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            ss.GetPublicId(),
				Version:       ss.GetVersion(),
				HostIds:       tc.setHosts,
			}

			got, err := s.SetHostSetHosts(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.NoError(t, err, "Got error: %v", s)
			assert.ElementsMatch(t, tc.resultHosts, got.GetItem().GetHostIds())
		})
	}

	ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	failCases := []struct {
		name    string
		req     *pbs.SetHostSetHostsRequest
		errCode codes.Code
	}{
		{
			name: "Bad Set Id",
			req: &pbs.SetHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            "bad id",
				Version:       ss.GetVersion(),
				HostIds:       []string{hs[0].GetPublicId()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Catalog Id",
			req: &pbs.SetHostSetHostsRequest{
				HostCatalogId: "bad catalog id",
				Id:            ss.GetPublicId(),
				Version:       ss.GetVersion(),
				HostIds:       []string{hs[0].GetPublicId()},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.SetHostSetHosts(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "SetHostSetHosts(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestRemoveHostSetHosts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	s, err := host_sets.NewService(repoFn)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestHosts(t, conn, hc.GetPublicId(), 4)

	removeCases := []struct {
		name        string
		setup       func(*static.HostSet)
		removeHosts []string
		resultHosts []string
		wantErr     bool
	}{
		{
			name:        "Remove host on empty set",
			setup:       func(r *static.HostSet) {},
			removeHosts: []string{hs[1].GetPublicId()},
			wantErr:     true,
		},
		{
			name: "Remove 1 of 2 hosts from set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:2])
			},
			removeHosts: []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
		{
			name: "Remove all hosts from set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:2])
			},
			removeHosts: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{},
		},
	}

	for _, tc := range removeCases {
		t.Run(tc.name, func(t *testing.T) {
			ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
			tc.setup(ss)
			req := &pbs.RemoveHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            ss.GetPublicId(),
				Version:       ss.GetVersion(),
				HostIds:       tc.removeHosts,
			}

			got, err := s.RemoveHostSetHosts(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHosts, got.GetItem().GetHostIds())
		})
	}

	ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	failCases := []struct {
		name    string
		req     *pbs.RemoveHostSetHostsRequest
		errCode codes.Code
	}{
		{
			name: "Bad catalog Id",
			req: &pbs.RemoveHostSetHostsRequest{
				HostCatalogId: "bad id",
				Id:            ss.GetPublicId(),
				Version:       ss.GetVersion(),
				HostIds:       []string{hs[0].GetPublicId()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad set Id",
			req: &pbs.RemoveHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            "bad id",
				Version:       ss.GetVersion(),
				HostIds:       []string{hs[0].GetPublicId()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "empty hosts",
			req: &pbs.RemoveHostSetHostsRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            "bad id",
				Version:       ss.GetVersion(),
				HostIds:       []string{},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.RemoveHostSetHosts(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "RemoveHostSetHosts(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}
