// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aliases_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/aliases"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func TestGet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(ctx, rw, rw, kmsCache)
	}
	_, p := iam.TestScopes(t, iamRepo)
	tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")
	og := target.TestAlias(t, rw, "test.get", target.WithName("alias name"), target.WithDescription("default"), target.WithDestinationId(tar.GetPublicId()), target.WithHostId("hst_1234567890"))

	toMerge := &pbs.GetAliasRequest{
		Id: og.GetPublicId(),
	}

	globalScopeInfo := &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: "global", Description: "Global Scope"}
	wantAlias := &pb.Alias{
		Type:          "target",
		Id:            og.GetPublicId(),
		ScopeId:       "global",
		Scope:         globalScopeInfo,
		Name:          wrapperspb.String(og.GetName()),
		Description:   wrapperspb.String(og.GetDescription()),
		CreatedTime:   og.CreateTime.GetTimestamp(),
		UpdatedTime:   og.UpdateTime.GetTimestamp(),
		Value:         og.GetValue(),
		Version:       1,
		DestinationId: wrapperspb.String(og.GetDestinationId()),
		Attrs: &pb.Alias_TargetAliasAttributes{
			TargetAliasAttributes: &pb.TargetAliasAttributes{
				AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
					HostId: og.GetHostId(),
				},
			},
		},
		AuthorizedActions: testAuthorizedActions,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetAliasRequest
		res     *pbs.GetAliasResponse
		err     error
	}{
		{
			name:    "Get an Existing Alias",
			scopeId: og.GetScopeId(),
			req:     &pbs.GetAliasRequest{Id: og.GetPublicId()},
			res:     &pbs.GetAliasResponse{Item: wantAlias},
		},
		{
			name: "Get a non existent Alias",
			req:  &pbs.GetAliasRequest{Id: globals.TargetAliasPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetAliasRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetAliasRequest{Id: globals.TargetAliasPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetAliasRequest)
			proto.Merge(req, tc.req)

			s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
			require.NoError(err, "Couldn't create new alias service.")

			got, gErr := s.GetAlias(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetAlias(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetAlias(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*target.Repository, error) {
		return repo, nil
	}

	var wantGlobalAliases []*pb.Alias
	for i := 0; i < 10; i++ {
		gg := target.TestAlias(t, rw, fmt.Sprintf("test%d.alias", i))
		wantGlobalAliases = append(wantGlobalAliases, &pb.Alias{
			Type:              "target",
			Id:                gg.GetPublicId(),
			ScopeId:           gg.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: "global", Description: "Global Scope"},
			CreatedTime:       gg.GetCreateTime().GetTimestamp(),
			UpdatedTime:       gg.GetUpdateTime().GetTimestamp(),
			Version:           1,
			Value:             gg.GetValue(),
			AuthorizedActions: testAuthorizedActions,
		})
	}

	slices.Reverse(wantGlobalAliases)

	cases := []struct {
		name string
		req  *pbs.ListAliasesRequest
		res  *pbs.ListAliasesResponse
		err  error
	}{
		{
			name: "List Global Aliases",
			req:  &pbs.ListAliasesRequest{ScopeId: "global"},
			res: &pbs.ListAliasesResponse{
				Items:        wantGlobalAliases,
				EstItemCount: uint32(len(wantGlobalAliases)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List global aliases recursively",
			req:  &pbs.ListAliasesRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListAliasesResponse{
				Items:        wantGlobalAliases,
				EstItemCount: uint32(len(wantGlobalAliases)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter to no aliases",
			req:  &pbs.ListAliasesRequest{ScopeId: "global", Recursive: true, Filter: `"/item/id"=="doesntmatch"`},
			res: &pbs.ListAliasesResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAliasesRequest{ScopeId: "global", Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
			require.NoError(err, "Couldn't create new alias service.")

			// Test with a non-anon user
			got, gErr := s.ListAliases(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAliases(%q) got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "ListAliases(%q) got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Test the anon case
			got, gErr = s.ListAliases(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.UpdatedTime)
				require.Zero(item.Version)
			}
		})
	}
}

func aliasToProto(u *target.Alias, si *scopes.ScopeInfo, authorizedActions []string) *pb.Alias {
	pu := &pb.Alias{
		Type:              "target",
		Id:                u.GetPublicId(),
		Value:             u.GetValue(),
		ScopeId:           u.GetScopeId(),
		Scope:             si,
		CreatedTime:       u.GetCreateTime().GetTimestamp(),
		UpdatedTime:       u.GetUpdateTime().GetTimestamp(),
		Version:           u.GetVersion(),
		AuthorizedActions: testAuthorizedActions,
	}
	if u.GetName() != "" {
		pu.Name = wrapperspb.String(u.GetName())
	}
	if u.GetDestinationId() != "" {
		pu.DestinationId = wrapperspb.String(u.GetDestinationId())
	}
	if u.GetHostId() != "" {
		pu.Attrs = &pb.Alias_TargetAliasAttributes{
			TargetAliasAttributes: &pb.TargetAliasAttributes{
				AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
					HostId: u.GetHostId(),
				},
			},
		}
	}
	if u.GetDescription() != "" {
		pu.Description = wrapperspb.String(u.GetDescription())
	}
	return pu
}

func TestListPagination(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDB, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	repo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*target.Repository, error) {
		return repo, nil
	}

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	tokenRepo, err := tokenRepoFn()
	require.NoError(t, err)

	// Run analyze to update postgres meta tables
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	authMethod := password.TestAuthMethods(t, conn, "global", 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")
	u := iam.TestUser(t, iamRepo, "global", iam.WithAccountIds(acct.PublicId))
	// add roles to be able to see all users
	allowedRole := iam.TestRole(t, conn, "global")
	iam.TestRoleGrant(t, conn, allowedRole.GetPublicId(), "id=*;type=*;actions=*")
	iam.TestUserRole(t, conn, allowedRole.GetPublicId(), u.GetPublicId())

	at, err := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	require.NoError(t, err)

	// Test without anon user
	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

	var globalAliases []*pb.Alias
	globalScopeInfo := &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: "global", Description: "Global Scope"}
	var safeToDeleteAlias string
	for i := 0; i < 10; i++ {
		gg := target.TestAlias(t, rw, fmt.Sprintf("test%d.alias", i))
		globalAliases = append(globalAliases, aliasToProto(gg, globalScopeInfo, testAuthorizedActions))
		safeToDeleteAlias = gg.GetPublicId()
	}
	slices.Reverse(globalAliases)

	a, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new alias service.")

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(context.Background(), "analyze")
	require.NoError(t, err)

	itemCount := uint32(len(globalAliases))
	testPageSize := int((itemCount - 2) / 2)

	// Start paginating, recursively
	req := &pbs.ListAliasesRequest{
		ScopeId:   "global",
		Recursive: true,
		Filter:    "",
		ListToken: "",
		PageSize:  uint32(testPageSize),
	}
	got, err := a.ListAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        globalAliases[0:testPageSize],
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				// In addition to the added aliases, there are the aliases added
				// by the test setup when specifying the permissions of the
				// requester
				EstItemCount: itemCount,
			},
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)

	// Request second page
	req.ListToken = got.ListToken
	got, err = a.ListAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        globalAliases[testPageSize : testPageSize*2],
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)

	// Request rest of results
	req.ListToken = got.ListToken
	req.PageSize = 10
	got, err = a.ListAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        globalAliases[testPageSize*2:],
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)

	// Update 2 aliases and see them in the refresh
	g1 := globalAliases[len(globalAliases)-1]
	g1.Description = wrapperspb.String("updated1")
	resp1, err := a.UpdateAlias(ctx, &pbs.UpdateAliasRequest{
		Id:         g1.GetId(),
		Item:       &pb.Alias{Description: g1.GetDescription(), Version: g1.GetVersion()},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err)
	g1.UpdatedTime = resp1.GetItem().GetUpdatedTime()
	g1.Version = resp1.GetItem().GetVersion()
	globalAliases = append([]*pb.Alias{g1}, globalAliases[:len(globalAliases)-1]...)

	g2 := globalAliases[len(globalAliases)-1]
	g2.Description = wrapperspb.String("updated2")
	resp2, err := a.UpdateAlias(ctx, &pbs.UpdateAliasRequest{
		Id:         g2.GetId(),
		Item:       &pb.Alias{Description: g2.GetDescription(), Version: g2.GetVersion()},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err)
	g2.UpdatedTime = resp2.GetItem().GetUpdatedTime()
	g2.Version = resp2.GetItem().GetVersion()
	globalAliases = append([]*pb.Alias{g2}, globalAliases[:len(globalAliases)-1]...)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Request updated results
	req.ListToken = got.ListToken
	req.PageSize = 1
	got, err = a.ListAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        []*pb.Alias{globalAliases[0]},
				ResponseType: "delta",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)

	// Get next page
	req.ListToken = got.ListToken
	got, err = a.ListAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        []*pb.Alias{globalAliases[1]},
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.ListToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, globalAliases[len(globalAliases)-2].Id, globalAliases[len(globalAliases)-1].Id)
	got, err = a.ListAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        []*pb.Alias{globalAliases[len(globalAliases)-2]},
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				// Should be empty again
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken
	// Get the second page
	got, err = a.ListAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        []*pb.Alias{globalAliases[len(globalAliases)-1]},
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)

	_, err = repo.DeleteAlias(ctx, safeToDeleteAlias)
	require.NoError(t, err)
	req.ListToken = got.ListToken
	got, err = a.ListAliases(ctx, req)
	require.NoError(t, err)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListAliasesResponse{
				Items:        nil,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   []string{safeToDeleteAlias},
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListAliasesResponse{}, "list_token"),
		),
	)
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, p := iam.TestScopes(t, iamRepo)

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(ctx, rw, rw, kmsCache)
	}
	tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")
	og := target.TestAlias(t, rw, "test.delete", target.WithDescription("default"), target.WithDestinationId(tar.GetPublicId()), target.WithHostId("hst_1234567890"))

	s, err := aliases.NewService(context.Background(), repoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Error when getting new alias service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteAliasRequest
		res     *pbs.DeleteAliasResponse
		err     error
	}{
		{
			name:    "Delete an Existing Alias",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteAliasRequest{
				Id: og.GetPublicId(),
			},
		},
		{
			name:    "Delete bad alias id",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteAliasRequest{
				Id: globals.TargetAliasPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Alias Id formatting",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteAliasRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteAlias(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteAlias(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteAlias(%+v) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(ctx, rw, rw, kmsCache)
	}
	og := target.TestAlias(t, rw, "test.delete", target.WithDescription("default"))

	s, err := aliases.NewService(context.Background(), repoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Error when getting new alias service")
	scopeId := og.GetScopeId()
	req := &pbs.DeleteAliasRequest{
		Id: og.GetPublicId(),
	}
	ctx = auth.DisabledAuthTestContext(iamRepoFn, scopeId)
	_, gErr := s.DeleteAlias(ctx, req)
	assert.NoError(t, gErr, "First attempt")
	_, gErr = s.DeleteAlias(ctx, req)
	assert.Error(t, gErr, "Second attempt")
	assert.True(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	_, p := iam.TestScopes(t, iamRepo)

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(ctx, rw, rw, kmsCache)
	}
	tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")
	al := target.TestAlias(t, rw, "test.duplicated.create",
		target.WithName("alias name"),
		target.WithDestinationId(tar.GetPublicId()))

	globalScopeInfo := &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: "global", Description: "Global Scope"}

	cases := []struct {
		name        string
		req         *pbs.CreateAliasRequest
		res         *pbs.CreateAliasResponse
		errContains string
	}{
		{
			name: "Create a valid Alias",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: scope.Global.String(),
				Value:   "valid.alias",
			}},
			res: &pbs.CreateAliasResponse{
				Uri: fmt.Sprintf("aliases/%s_", globals.TargetAliasPrefix),
				Item: &pb.Alias{
					Type:              "target",
					ScopeId:           scope.Global.String(),
					Scope:             globalScopeInfo,
					Value:             "valid.alias",
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Alias to existing target",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:          "target",
				ScopeId:       scope.Global.String(),
				Value:         "target-assigned.valid.alias",
				DestinationId: wrapperspb.String(tar.GetPublicId()),
			}},
			res: &pbs.CreateAliasResponse{
				Uri: fmt.Sprintf("aliases/%s_", globals.TargetAliasPrefix),
				Item: &pb.Alias{
					Type:              "target",
					ScopeId:           scope.Global.String(),
					Scope:             globalScopeInfo,
					Value:             "target-assigned.valid.alias",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Alias to poorly formatted target id",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:          "target",
				ScopeId:       scope.Global.String(),
				Value:         "target-assigned.valid.alias",
				DestinationId: wrapperspb.String("this is not a valid target id"),
			}},
			errContains: `Incorrectly formatted identifier.`,
		},
		{
			name: "Alias to existing target with static host id",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: scope.Global.String(),
				Value:   "target-assigned.valid.alias.two",
				Attrs: &pb.Alias_TargetAliasAttributes{
					TargetAliasAttributes: &pb.TargetAliasAttributes{
						AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
							HostId: "hst_1234567890",
						},
					},
				},
				DestinationId: wrapperspb.String(tar.GetPublicId()),
			}},
			res: &pbs.CreateAliasResponse{
				Uri: fmt.Sprintf("aliases/%s_", globals.TargetAliasPrefix),
				Item: &pb.Alias{
					Type:    "target",
					ScopeId: scope.Global.String(),
					Scope:   globalScopeInfo,
					Value:   "target-assigned.valid.alias.two",
					Attrs: &pb.Alias_TargetAliasAttributes{
						TargetAliasAttributes: &pb.TargetAliasAttributes{
							AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
								HostId: "hst_1234567890",
							},
						},
					},
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Alias to existing target with dynamic host id",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: scope.Global.String(),
				Value:   "target-assigned.valid.alias.three",
				Attrs: &pb.Alias_TargetAliasAttributes{
					TargetAliasAttributes: &pb.TargetAliasAttributes{
						AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
							HostId: "hplg_1234567890",
						},
					},
				},
				DestinationId: wrapperspb.String(tar.GetPublicId()),
			}},
			res: &pbs.CreateAliasResponse{
				Uri: fmt.Sprintf("aliases/%s_", globals.TargetAliasPrefix),
				Item: &pb.Alias{
					Type:    "target",
					ScopeId: scope.Global.String(),
					Scope:   globalScopeInfo,
					Value:   "target-assigned.valid.alias.three",
					Attrs: &pb.Alias_TargetAliasAttributes{
						TargetAliasAttributes: &pb.TargetAliasAttributes{
							AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
								HostId: "hplg_1234567890",
							},
						},
					},
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Omitting the alias type",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				ScopeId:       scope.Global.String(),
				Value:         "target-assigned.valid.alias",
				DestinationId: wrapperspb.String(tar.GetPublicId()),
			}},
			errContains: `This field is required`,
		},
		{
			name: "host id with no destination target",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: scope.Global.String(),
				Value:   "host-id.no-destination.alias",
				Attrs: &pb.Alias_TargetAliasAttributes{
					TargetAliasAttributes: &pb.TargetAliasAttributes{
						AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
							HostId: "hst_1234567890",
						},
					},
				},
			}},
			errContains: `This field is required when 'attributes.authorize_session_arguments.host_id' is specified.`,
		},
		{
			name: "improperly formatted host id",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:          "target",
				ScopeId:       scope.Global.String(),
				Value:         "bad-host-id.alias",
				DestinationId: wrapperspb.String(tar.GetPublicId()),
				Attrs: &pb.Alias_TargetAliasAttributes{
					TargetAliasAttributes: &pb.TargetAliasAttributes{
						AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
							HostId: "badid_1234567890",
						},
					},
				},
			}},
			errContains: `Incorrectly formatted identifier.`,
		},
		{
			name: "Alias to non existing target",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:          "target",
				ScopeId:       scope.Global.String(),
				Value:         "unknowntarget.alias",
				DestinationId: wrapperspb.String("ttcp_1234567890"),
			}},
			errContains: `target with specified destination id "ttcp_1234567890" was not found`,
		},
		{
			name: "Duplicate Alias Value",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: scope.Global.String(),
				Value:   al.GetValue(),
			}},
			errContains: `alias value "test.duplicated.create" is already in use`,
		},
		{
			name: "Duplicate Alias Name",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: scope.Global.String(),
				Value:   "duplicate.alias.name",
				Name:    wrapperspb.String(al.GetName()),
			}},
			errContains: `name "alias name" is already in use`,
		},
		{
			name: "must be in global scope",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: p.GetPublicId(),
				Value:   "must.be.in.global.scope",
			}},
			errContains: `{name: "scope_id", desc: "This field is missing or improperly formatted."}`,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:    "target",
				ScopeId: scope.Global.String(),
				Id:      globals.TargetAliasPrefix + "_notallowed",
			}},
			res:         nil,
			errContains: "This is a read only field.",
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:        "target",
				ScopeId:     scope.Global.String(),
				CreatedTime: timestamppb.Now(),
			}},
			res:         nil,
			errContains: "This is a read only field.",
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAliasRequest{Item: &pb.Alias{
				Type:        "target",
				ScopeId:     scope.Global.String(),
				UpdatedTime: timestamppb.Now(),
			}},
			res:         nil,
			errContains: "This is a read only field.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := aliases.NewService(context.Background(), repoFn, iamRepoFn, 1000)
			require.NoError(err, "Error when getting new alias service.")

			got, gErr := s.CreateAlias(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetItem().GetScopeId()), tc.req)
			if tc.errContains != "" {
				require.Error(gErr)
				assert.ErrorContains(gErr, tc.errContains)
				return
			}
			require.NoError(gErr)
			assert.Contains(got.GetUri(), tc.res.Uri)
			assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.TargetAliasPrefix+"_"))
			// Clear all values which are hard to compare against.
			got.Uri, tc.res.Uri = "", ""
			got.Item.Id, tc.res.Item.Id = "", ""
			got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateAlias(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, p := iam.TestScopes(t, iamRepo)
	tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")
	tar2 := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget2")

	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(ctx, rw, rw, kmsCache)
	}

	og := target.TestAlias(t, rw, "default",
		target.WithDestinationId(tar.GetPublicId()),
		target.WithName("default"),
		target.WithDescription("default"))

	var ogVersion uint32 = 1

	resetAlias := func(version uint32) {
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		og, _, err = repo.UpdateAlias(ctx, og, version, []string{"Name", "Description", "DestinationId", "Value"})
		require.NoError(t, err, "Failed to reset the alias")
		ogVersion = og.GetVersion()
	}

	created := og.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateAliasRequest{
		Id: og.GetPublicId(),
	}
	globalScopeInfo := &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: "global", Description: "Global Scope"}

	tested, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Error creating new service")
	cases := []struct {
		name    string
		scopeId string
		req     *pbs.UpdateAliasRequest
		res     *pbs.UpdateAliasResponse
		err     error
	}{
		{
			name:    "Update an Existing Alias",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Alias{
					Name:        wrapperspb.String("updated"),
					Description: wrapperspb.String("updated"),
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Name:              wrapperspb.String("updated"),
					Description:       wrapperspb.String("updated"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Alias{
					Name:        wrapperspb.String("updated"),
					Description: wrapperspb.String("updated"),
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Name:              wrapperspb.String("updated"),
					Description:       wrapperspb.String("updated"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAliasRequest{
				Item: &pb.Alias{
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "No Paths in Mask",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Alias{
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Only non-existent paths in Mask",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Alias{
					Description: wrapperspb.String("updated desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Unset Name",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Alias{
					Description: wrapperspb.String("ignored"),
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Description:       wrapperspb.String("default"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Update Only Name",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Alias{
					Name:        wrapperspb.String("updated"),
					Description: wrapperspb.String("ignored"),
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					Name:              wrapperspb.String("updated"),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Description:       wrapperspb.String("default"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Update Only value",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"value"},
				},
				Item: &pb.Alias{
					Name:  wrapperspb.String("ignored"),
					Value: "updated",
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "updated",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Name:              wrapperspb.String("default"),
					Description:       wrapperspb.String("default"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Update destination id",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"destination_id"},
				},
				Item: &pb.Alias{
					Name:          wrapperspb.String("ignored"),
					DestinationId: wrapperspb.String("invalid format for targets"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "unset value",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"value"},
				},
				Item: &pb.Alias{
					Name: wrapperspb.String("ignored"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Update Only destination id",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"destination_id"},
				},
				Item: &pb.Alias{
					Value:         "ignored",
					DestinationId: wrapperspb.String(tar2.GetPublicId()),
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar2.GetPublicId()),
					Name:              wrapperspb.String("default"),
					Description:       wrapperspb.String("default"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Unset destination id",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"destination_id"},
				},
				Item: &pb.Alias{
					Value: "ignored",
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					Name:              wrapperspb.String("default"),
					Description:       wrapperspb.String("default"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Update Only Description",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Alias{
					Description: wrapperspb.String("updated"),
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Name:              wrapperspb.String("default"),
					Description:       wrapperspb.String("updated"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Alias",
			req: &pbs.UpdateAliasRequest{
				Id: globals.TargetAliasPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Alias{
					Description: wrapperspb.String("desc"),
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateAliasRequest{
				Id: og.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Alias{
					Id:          globals.TargetAliasPrefix + "_somethinge",
					Description: wrapperspb.String("new desc"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant use invalid host id",
			req: &pbs.UpdateAliasRequest{
				Id: og.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"host_id"},
				},
				Item: &pb.Alias{
					Description: wrapperspb.String("new desc"),
					Attrs: &pb.Alias_TargetAliasAttributes{
						&pb.TargetAliasAttributes{
							AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
								HostId: "badid_1234567890",
							},
						},
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update with static host id",
			req: &pbs.UpdateAliasRequest{
				Id: og.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.authorize_session_arguments.host_id"},
				},
				Item: &pb.Alias{
					Description: wrapperspb.String("new desc"),
					Attrs: &pb.Alias_TargetAliasAttributes{
						&pb.TargetAliasAttributes{
							AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
								HostId: "hst_1234567890",
							},
						},
					},
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					Name:              wrapperspb.String("default"),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Description:       wrapperspb.String("default"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
					Attrs: &pb.Alias_TargetAliasAttributes{
						&pb.TargetAliasAttributes{
							AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
								HostId: "hst_1234567890",
							},
						},
					},
				},
			},
		},
		{
			name: "Update with dynamic host id",
			req: &pbs.UpdateAliasRequest{
				Id: og.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.authorize_session_arguments.host_id"},
				},
				Item: &pb.Alias{
					Description: wrapperspb.String("new desc"),
					Attrs: &pb.Alias_TargetAliasAttributes{
						&pb.TargetAliasAttributes{
							AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
								HostId: "hplg_1234567890",
							},
						},
					},
				},
			},
			res: &pbs.UpdateAliasResponse{
				Item: &pb.Alias{
					Type:              "target",
					Id:                og.GetPublicId(),
					Name:              wrapperspb.String("default"),
					ScopeId:           og.GetScopeId(),
					Scope:             globalScopeInfo,
					Value:             "default",
					DestinationId:     wrapperspb.String(tar.GetPublicId()),
					Description:       wrapperspb.String("default"),
					CreatedTime:       og.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
					Attrs: &pb.Alias_TargetAliasAttributes{
						&pb.TargetAliasAttributes{
							AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
								HostId: "hplg_1234567890",
							},
						},
					},
				},
			},
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Alias{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateAliasRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Alias{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver := ogVersion
			tc.req.Item.Version = ver

			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateAliasRequest)
			proto.Merge(req, tc.req)

			// Test with bad version (too high, too low)
			req.Item.Version = ver + 2
			_, gErr := tested.UpdateAlias(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), req)
			require.Error(gErr)
			req.Item.Version = ver - 1
			_, gErr = tested.UpdateAlias(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), req)
			require.Error(gErr)
			req.Item.Version = ver

			got, gErr := tested.UpdateAlias(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAlias(%+v) got error %v, wanted %v", req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			defer resetAlias(got.GetItem().GetVersion())

			assert.NotNilf(tc.res, "Expected UpdateAlias response to be nil, but was %v", got)
			gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
			// Verify it is a alias updated after it was created
			assert.True(gotUpdateTime.After(created), "Updated alias should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

			// Clear all values which are hard to compare against.
			got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

			assert.Equal(ver+1, got.GetItem().GetVersion())
			tc.res.Item.Version = ver + 1
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "UpdateAlias(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
