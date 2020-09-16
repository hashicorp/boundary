package hosts_test

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
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
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
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	pHost := &pb.Host{
		HostCatalogId: hc.GetPublicId(),
		Id:            h.GetPublicId(),
		CreatedTime:   h.CreateTime.GetTimestamp(),
		UpdatedTime:   h.UpdateTime.GetTimestamp(),
		Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		Type:          "static",
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"address": structpb.NewStringValue(h.GetAddress()),
		}},
	}

	cases := []struct {
		name    string
		req     *pbs.GetHostRequest
		res     *pbs.GetHostResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Host",
			req:     &pbs.GetHostRequest{Id: h.GetPublicId()},
			res:     &pbs.GetHostResponse{Item: pHost},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing Host Set",
			req:     &pbs.GetHostRequest{Id: static.HostPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetHostRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetHostRequest{Id: static.HostPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			s, err := hosts.NewService(repoFn)
			require.NoError(t, err, "Couldn't create a new host set service.")

			got, gErr := s.GetHost(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
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

	var wantHs []*pb.Host
	for _, h := range static.TestHosts(t, conn, hc.GetPublicId(), 10) {
		wantHs = append(wantHs, &pb.Host{
			Id:            h.GetPublicId(),
			HostCatalogId: h.GetCatalogId(),
			Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
			CreatedTime:   h.GetCreateTime().GetTimestamp(),
			UpdatedTime:   h.GetUpdateTime().GetTimestamp(),
			Version:       h.GetVersion(),
			Type:          host.StaticSubtype.String(), Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"address": structpb.NewStringValue(h.GetAddress()),
			}},
		})
	}

	cases := []struct {
		name          string
		hostCatalogId string
		res           *pbs.ListHostsResponse
		errCode       codes.Code
	}{
		{
			name:          "List Many Hosts",
			hostCatalogId: hc.GetPublicId(),
			res:           &pbs.ListHostsResponse{Items: wantHs},
			errCode:       codes.OK,
		},
		{
			name:          "List No Hosts",
			hostCatalogId: hcNoHosts.GetPublicId(),
			res:           &pbs.ListHostsResponse{},
			errCode:       codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(repoFn)
			require.NoError(err, "Couldn't create new host set service.")

			got, gErr := s.ListHosts(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), &pbs.ListHostsRequest{HostCatalogId: tc.hostCatalogId})
			assert.Equal(tc.errCode, status.Code(gErr), "ListHosts(%q) got error %v, wanted %v", tc.hostCatalogId, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHosts(%q) got response %q, wanted %q", tc.hostCatalogId, got, tc.res)
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
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	s, err := hosts.NewService(repoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteHostRequest
		res     *pbs.DeleteHostResponse
		errCode codes.Code
	}{
		{
			name:    "Delete an Existing Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: h.GetPublicId(),
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad id Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: static.HostPrefix + "_doesntexis",
			},
			errCode: codes.NotFound,
		},
		{
			name:    "Bad Host Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: static.HostPrefix + "_bad_format",
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteHost(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "DeleteHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	s, err := hosts.NewService(repoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")
	req := &pbs.DeleteHostRequest{
		Id: h.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId()))
	_, gErr := s.DeleteHost(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteHost(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.Equal(codes.NotFound, status.Code(gErr), "Expected permission denied for the second delete.")
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

	defaultHcCreated, err := ptypes.Timestamp(hc.GetCreateTime().GetTimestamp())
	require.NoError(t, err)

	cases := []struct {
		name    string
		req     *pbs.CreateHostRequest
		res     *pbs.CreateHostResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid Host",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"address": structpb.NewStringValue("123.456.789"),
				}},
			}},
			res: &pbs.CreateHostResponse{
				Uri: fmt.Sprintf("hosts/%s_", static.HostPrefix),
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "name"},
					Description:   &wrappers.StringValue{Value: "desc"},
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("123.456.789"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Create with empty address",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"address": structpb.NewStringValue(""),
				}},
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create without address",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attributes:    &structpb.Struct{Fields: map[string]*structpb.Value{}},
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "ThisIsMadeUp",
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "no type name"},
				Description:   &wrappers.StringValue{Value: "no type desc"},
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"address": structpb.NewStringValue("123.456.789"),
				}},
			}},
			res: &pbs.CreateHostResponse{
				Uri: fmt.Sprintf("hosts/%s_", static.HostPrefix),
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "no type name"},
					Description:   &wrappers.StringValue{Value: "no type desc"},
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("123.456.789"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Id:            "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				CreatedTime:   ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(repoFn)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHost(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostPrefix))
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a set created after the test setup's default set
				assert.True(gotCreateTime.After(defaultHcCreated), "New host should have been created after default host. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New host should have been updated after default host. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
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

	h, err := static.NewHost(hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"), static.WithAddress("defaultaddress"))
	require.NoError(t, err)
	h, err = repo.CreateHost(context.Background(), proj.GetPublicId(), h)
	require.NoError(t, err)

	var version uint32 = 1

	resetHost := func() {
		version++
		_, _, err = repo.UpdateHost(context.Background(), proj.GetPublicId(), h, version, []string{"Name", "Description", "Address"})
		require.NoError(t, err, "Failed to reset host.")
		version++
	}

	hCreated, err := ptypes.Timestamp(h.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Failed to convert proto to timestamp")
	toMerge := &pbs.UpdateHostRequest{
		Id: h.GetPublicId(),
	}

	tested, err := hosts.NewService(repoFn)
	require.NoError(t, err, "Failed to create a new host set service.")

	cases := []struct {
		name    string
		req     *pbs.UpdateHostRequest
		res     *pbs.UpdateHostResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing Host",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "type"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "new"},
					Description:   &wrappers.StringValue{Value: "desc"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "new"},
					Description:   &wrappers.StringValue{Value: "desc"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostRequest{
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,type"},
				},
				Item: &pb.Host{
					Name: &wrappers.StringValue{Value: "updated name"},
					Type: "ec2",
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Host{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Description:   &wrappers.StringValue{Value: "default"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Host{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "default"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "updated"},
					Description:   &wrappers.StringValue{Value: "default"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:          &wrappers.StringValue{Value: "default"},
					Description:   &wrappers.StringValue{Value: "notignored"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update a Non Existing Host",
			req: &pbs.UpdateHostRequest{
				Id: static.HostPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			errCode: codes.NotFound,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Host{
					Id:          "p_somethinge",
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant unset address",
			req: &pbs.UpdateHostRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.address"},
				},
				Item: &pb.Host{
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewNullValue(),
					}},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant set address to empty string",
			req: &pbs.UpdateHostRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.address"},
				},
				Item: &pb.Host{
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue(""),
					}},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Host{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Host{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Host{
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

			req := proto.Clone(toMerge).(*pbs.UpdateHostRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Item.Version = version + 2
			_, gErr := tested.UpdateHost(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateHost(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateHost(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateHost(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.errCode == codes.OK {
				defer resetHost()
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateHost(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
