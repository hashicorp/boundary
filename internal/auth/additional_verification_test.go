package auth_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/roles"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestAdditionalVerification(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	conn := tc.DbConn()
	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	or := iam.TestRole(t, conn, org.GetPublicId(), iam.WithGrantScopeId(proj.GetPublicId()))
	pr := iam.TestRole(t, conn, proj.GetPublicId())

	defaultCreated, err := ptypes.Timestamp(defaultOrgRole.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateRoleRequest{}

	cases := []struct {
		name string
		req  *pbs.CreateRoleRequest
		res  *pbs.CreateRoleResponse
		err  error
	}{
		{
			name: "Create a valid Role",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:      defaultOrgRole.GetScopeId(),
				Name:         &wrapperspb.StringValue{Value: "name"},
				Description:  &wrapperspb.StringValue{Value: "desc"},
				GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
			}},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("roles/%s_", iam.RolePrefix),
				Item: &pb.Role{
					ScopeId:      defaultOrgRole.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: defaultOrgRole.GetScopeId(), Type: scope.Org.String()},
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
		},
		{
			name: "Create a valid Global Role",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:      scope.Global.String(),
				Name:         &wrapperspb.StringValue{Value: "name"},
				Description:  &wrapperspb.StringValue{Value: "desc"},
				GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
			}},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("roles/%s_", iam.RolePrefix),
				Item: &pb.Role{
					ScopeId:      scope.Global.String(),
					Scope:        &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String()},
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
		},
		{
			name: "Create a valid Project Scoped Role",
			req: &pbs.CreateRoleRequest{
				Item: &pb.Role{
					ScopeId:     defaultProjRole.GetScopeId(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("roles/%s_", iam.RolePrefix),
				Item: &pb.Role{
					ScopeId:      defaultProjRole.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: defaultProjRole.GetScopeId(), Type: scope.Project.String()},
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
		},
		{
			name: "Invalid grant scope ID",
			req: &pbs.CreateRoleRequest{
				Item: &pb.Role{
					ScopeId:      defaultProjRole.GetScopeId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultOrgRole.GetScopeId()},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId: defaultProjRole.GetScopeId(),
				Id:      iam.RolePrefix + "_notallowed",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:     defaultProjRole.GetScopeId(),
				CreatedTime: ptypes.TimestampNow(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:     defaultProjRole.GetScopeId(),
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateRoleRequest)
			proto.Merge(req, tc.req)

			s, err := roles.NewService(repo)
			require.NoError(err, "Error when getting new role service.")

			got, gErr := s.CreateRole(auth.DisabledAuthTestContext(auth.WithScopeId(tc.req.GetItem().GetScopeId())), req)
			if tc.err != nil {
				require.NotNil(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateRole(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), iam.RolePrefix+"_"), "Expected %q to have the prefix %q", got.GetItem().GetId(), iam.RolePrefix+"_")
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a role created after the test setup's default role
				assert.True(gotCreateTime.After(defaultCreated), "New role should have been created after default role. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New role should have been updated after default role. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateRole(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}
