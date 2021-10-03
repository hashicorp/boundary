package credentiallibraries

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}

	_, prjNoLibs := iam.TestScopes(t, iamRepo)
	storeNoLibs := vault.TestCredentialStores(t, conn, wrapper, prjNoLibs.GetPublicId(), 1)[0]
	_, prj := iam.TestScopes(t, iamRepo)

	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	var wantLibraries []*pb.CredentialLibrary
	for _, l := range vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 10) {
		wantLibraries = append(wantLibraries, &pb.CredentialLibrary{
			Id:                l.GetPublicId(),
			CredentialStoreId: l.GetStoreId(),
			Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
			CreatedTime:       l.GetCreateTime().GetTimestamp(),
			UpdatedTime:       l.GetUpdateTime().GetTimestamp(),
			Version:           l.GetVersion(),
			Type:              vault.Subtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attributes: func() *structpb.Struct {
				attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
					Path:       wrapperspb.String(l.GetVaultPath()),
					HttpMethod: wrapperspb.String(l.GetHttpMethod()),
				})
				require.NoError(t, err)
				return attrs
			}(),
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListCredentialLibrariesRequest
		res  *pbs.ListCredentialLibrariesResponse
		err  error
	}{
		{
			name: "List Many Libraries",
			req:  &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId()},
			res:  &pbs.ListCredentialLibrariesResponse{Items: wantLibraries},
		},
		{
			name: "List No Libraries",
			req:  &pbs.ListCredentialLibrariesRequest{CredentialStoreId: storeNoLibs.GetPublicId()},
			res:  &pbs.ListCredentialLibrariesResponse{},
		},
		{
			name: "Filter to One Libraries",
			req:  &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantLibraries[1].GetId())},
			res:  &pbs.ListCredentialLibrariesResponse{Items: wantLibraries[1:2]},
		},
		{
			name: "Filter to No Libraries",
			req:  &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:  &pbs.ListCredentialLibrariesResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(repoFn, iamRepoFn)
			require.NoError(t, err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "ListCredentialLibrary(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(t, gErr)
			sort.Slice(got.Items, func(i, j int) bool {
				return got.Items[i].GetId() < got.Items[j].GetId()
			})
			want := proto.Clone(tc.res).(*pbs.ListCredentialLibrariesResponse)
			sort.Slice(want.Items, func(i, j int) bool {
				return want.Items[i].GetId() < want.Items[j].GetId()
			})
			assert.Empty(t, cmp.Diff(got, want, protocmp.Transform()))

			// Test anonymous listing
			got, gErr = s.ListCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
			require.NoError(t, gErr)
			assert.Len(t, got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(t, item.CreatedTime)
				require.Nil(t, item.UpdatedTime)
				require.Zero(t, item.Version)
			}
		})
	}
}

func TestCreate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	defaultCL := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
	defaultCreated := defaultCL.GetCreateTime().GetTimestamp()

	cases := []struct {
		name     string
		req      *pbs.CreateCredentialLibraryRequest
		res      *pbs.CreateCredentialLibraryResponse
		idPrefix string
		err      error
		wantErr  bool
	}{
		{
			name: "missing vault path",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialLibraryPrefix + "_",
			wantErr:  true,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Id:                vault.CredentialLibraryPrefix + "_notallowed",
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				CreatedTime:       timestamppb.Now(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				UpdatedTime:       timestamppb.Now(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Type and parent id must match",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              "static",
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "parent id must be included",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				Type: vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Attributes must be valid for vault type",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					})
					require.NoError(t, err)
					attrs.Fields["invalid"] = structpb.NewStringValue("foo")
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cannot specify a http request body when http method is get",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path:            wrapperspb.String("something"),
						HttpRequestBody: wrapperspb.String("foo"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid Method",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path:       wrapperspb.String("something"),
						HttpMethod: wrapperspb.String("PATCH"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Request Body With GET Method",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path:            wrapperspb.String("something"),
						HttpRequestBody: wrapperspb.String("foo"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Using POST method",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path:            wrapperspb.String("something"),
						HttpMethod:      wrapperspb.String("post"),
						HttpRequestBody: wrapperspb.String("foo"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", vault.CredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.Subtype.String(),
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
							Path:            wrapperspb.String("something"),
							HttpMethod:      wrapperspb.String("POST"),
							HttpRequestBody: wrapperspb.String("foo"),
						})
						require.NoError(t, err)
						return attrs
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Name:              &wrapperspb.StringValue{Value: "name"},
				Description:       &wrapperspb.StringValue{Value: "desc"},
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", vault.CredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.Subtype.String(),
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						})
						require.NoError(t, err)
						return attrs
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(repoFn, iamRepoFn)
			require.NoError(err, "Error when getting new credential store service.")

			got, gErr := s.CreateCredentialLibrary(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), tc.req)
			if tc.wantErr || tc.err != nil {
				require.Error(gErr)
				if tc.err != nil {
					assert.True(errors.Is(gErr, tc.err), "CreateCredentialLibrary(...) got error %v, wanted %v", gErr, tc.err)
				}
				return
			}
			require.NoError(gErr)
			if tc.res == nil {
				require.Nil(got)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), tc.idPrefix))
				gotCreateTime := got.GetItem().GetCreatedTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime()

				// Verify it is a credential store created after the test setup's default credential store
				assert.True(gotCreateTime.AsTime().After(defaultCreated.AsTime()), "New credential store should have been created after default credential store. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.AsTime().After(defaultCreated.AsTime()), "New credential store should have been updated after default credential store. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "CreateCredentialLibrary(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)

	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	vl := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
	s, err := NewService(repoFn, iamRepoFn)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		res  *pbs.GetCredentialLibraryResponse
		err  error
	}{
		{
			name: "success",
			id:   vl.GetPublicId(),
			res: &pbs.GetCredentialLibraryResponse{
				Item: &pb.CredentialLibrary{
					Id:                vl.GetPublicId(),
					CredentialStoreId: vl.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetScopeId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              vault.Subtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       vl.CreateTime.GetTimestamp(),
					UpdatedTime:       vl.UpdateTime.GetTimestamp(),
					Version:           1,
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String(vl.GetVaultPath()),
							HttpMethod: wrapperspb.String(vl.GetHttpMethod()),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", vault.CredentialLibraryPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", static.HostPrefix),
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.GetCredentialLibraryRequest{Id: tc.id}
			// Test non-anonymous get
			got, gErr := s.GetCredentialLibrary(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err))
				return
			}
			require.NoError(t, gErr)
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform()))

			// Test anonymous get
			got, gErr = s.GetCredentialLibrary(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), req)
			require.NoError(t, gErr)
			require.Nil(t, got.Item.CreatedTime)
			require.Nil(t, got.Item.UpdatedTime)
			require.Zero(t, got.Item.Version)
		})
	}
}

func TestDelete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)

	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	vl := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
	s, err := NewService(repoFn, iamRepoFn)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		err  error
		res  *pbs.DeleteCredentialLibraryResponse
	}{
		{
			name: "success",
			id:   vl.GetPublicId(),
			res:  &pbs.DeleteCredentialLibraryResponse{},
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", vault.CredentialLibraryPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", static.HostPrefix),
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gErr := s.DeleteCredentialLibrary(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), &pbs.DeleteCredentialLibraryRequest{Id: tc.id})
			assert.EqualValuesf(t, tc.res, got, "DeleteCredentialLibrary got response %q, wanted %q", got, tc.res)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err))
				return
			}
			require.NoError(t, gErr)
			g, err := s.GetCredentialLibrary(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), &pbs.GetCredentialLibraryRequest{Id: tc.id})
			assert.Nil(t, g)
			assert.True(t, errors.Is(err, handlers.NotFoundError()))
		})
	}
}

func TestUpdate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())

	s, err := NewService(repoFn, iamRepoFn)
	require.NoError(t, err)
	cs := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)
	store, diffStore := cs[0], cs[1]

	freshLibrary := func() (*vault.CredentialLibrary, func()) {
		vl := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
		clean := func() {
			_, err := s.DeleteCredentialLibrary(ctx, &pbs.DeleteCredentialLibraryRequest{Id: vl.GetPublicId()})
			require.NoError(t, err)
		}
		return vl, clean
	}

	fieldmask := func(paths ...string) *fieldmaskpb.FieldMask {
		return &fieldmaskpb.FieldMask{Paths: paths}
	}

	v := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS))
	_, token := v.CreateToken(t)
	_ = token

	successCases := []struct {
		name string
		req  *pbs.UpdateCredentialLibraryRequest
		res  func(*pb.CredentialLibrary) *pb.CredentialLibrary
	}{
		{
			name: "name and description",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask("name", "description"),
				Item: &pb.CredentialLibrary{
					Name:        wrapperspb.String("basic"),
					Description: wrapperspb.String("basic"),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.Name = wrapperspb.String("basic")
				out.Description = wrapperspb.String("basic")
				return out
			},
		},
		{
			name: "update method",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(httpMethodField),
				Item: &pb.CredentialLibrary{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
							HttpMethod: wrapperspb.String("pOsT"),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.Attributes.Fields["path"] = structpb.NewStringValue("vault/path0")
				out.Attributes.Fields["http_method"] = structpb.NewStringValue("POST")
				return out
			},
		},
		{
			name: "update request body and method",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(httpRequestBodyField, httpMethodField),
				Item: &pb.CredentialLibrary{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
							HttpMethod:      wrapperspb.String("pOsT"),
							HttpRequestBody: wrapperspb.String("body"),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.Attributes.Fields["path"] = structpb.NewStringValue("vault/path0")
				out.Attributes.Fields["http_method"] = structpb.NewStringValue("POST")
				out.Attributes.Fields["http_request_body"] = structpb.NewStringValue("body")
				return out
			},
		},
		{
			name: "update path",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(vaultPathField),
				Item: &pb.CredentialLibrary{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialLibraryAttributes{
							Path: wrapperspb.String("something"),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.Attributes.Fields["path"] = structpb.NewStringValue("something")
				return out
			},
		},
	}

	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			st, cleanup := freshLibrary()
			defer cleanup()

			if tc.req.Item.GetVersion() == 0 {
				tc.req.Item.Version = 1
			}
			if tc.req.GetId() == "" {
				tc.req.Id = st.GetPublicId()
			}
			resToChange, err := s.GetCredentialLibrary(ctx, &pbs.GetCredentialLibraryRequest{Id: st.GetPublicId()})
			require.NoError(err)
			want := &pbs.UpdateCredentialLibraryResponse{Item: tc.res(resToChange.GetItem())}

			got, gErr := s.UpdateCredentialLibrary(ctx, tc.req)
			require.NoError(gErr)
			require.NotNil(got)

			gotUpdateTime := got.GetItem().GetUpdatedTime()
			created := st.GetCreateTime().GetTimestamp()
			assert.True(gotUpdateTime.AsTime().After(created.AsTime()), "Should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

			want.Item.UpdatedTime = got.Item.UpdatedTime

			assert.EqualValues(2, got.Item.Version)
			want.Item.Version = 2

			assert.Empty(cmp.Diff(got, want, protocmp.Transform()))
		})
	}

	vl, cleanup := freshLibrary()
	defer cleanup()

	errCases := []struct {
		name string
		path string
		item *pb.CredentialLibrary
	}{
		{
			name: "read only type",
			path: "type",
			item: &pb.CredentialLibrary{Type: "something"},
		},
		{
			name: "read only store_id",
			path: "store_id",
			item: &pb.CredentialLibrary{CredentialStoreId: diffStore.GetPublicId()},
		},
		{
			name: "read only updated_time",
			path: "updated_time",
			item: &pb.CredentialLibrary{UpdatedTime: timestamppb.Now()},
		},
		{
			name: "read only created_time",
			path: "created_time",
			item: &pb.CredentialLibrary{UpdatedTime: timestamppb.Now()},
		},
		{
			name: "read only authorized actions",
			path: "authorized actions",
			item: &pb.CredentialLibrary{AuthorizedActions: append(testAuthorizedActions, "another")},
		},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.UpdateCredentialLibraryRequest{
				Id:         vl.GetPublicId(),
				Item:       tc.item,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{tc.path}},
			}
			req.Item.Version = vl.Version

			got, gErr := s.UpdateCredentialLibrary(ctx, req)
			assert.Error(t, gErr)
			assert.Truef(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)), "got error %v, wanted invalid argument", gErr)
			assert.Nil(t, got)
		})
	}

	t.Run("request body and method interactions", func(t *testing.T) {
		vl, cleanup := freshLibrary()
		defer cleanup()
		require.Equal(t, "GET", vl.GetHttpMethod())

		// Cannot set request body on GET request
		cl, err := s.UpdateCredentialLibrary(ctx, &pbs.UpdateCredentialLibraryRequest{
			Id:         vl.GetPublicId(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{httpRequestBodyField}},
			Item: &pb.CredentialLibrary{
				Version: vl.GetVersion(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"http_request_body": structpb.NewStringValue("body"),
					},
				},
			},
		})
		require.Error(t, err)
		require.Nil(t, cl)

		// Can set POST when there is no request body
		cl, err = s.UpdateCredentialLibrary(ctx, &pbs.UpdateCredentialLibraryRequest{
			Id:         vl.GetPublicId(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{httpMethodField}},
			Item: &pb.CredentialLibrary{
				Version: vl.GetVersion(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"http_method": structpb.NewStringValue("POST"),
					},
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, cl)
		require.Equal(t, "POST", cl.GetItem().GetAttributes().GetFields()["http_method"].GetStringValue())

		// Can set request body on POST
		cl, err = s.UpdateCredentialLibrary(ctx, &pbs.UpdateCredentialLibraryRequest{
			Id:         vl.GetPublicId(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{httpRequestBodyField}},
			Item: &pb.CredentialLibrary{
				Version: cl.Item.GetVersion(),
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"http_request_body": structpb.NewStringValue("body"),
					},
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, cl)
		require.Equal(t, "POST", cl.GetItem().GetAttributes().GetFields()["http_method"].GetStringValue())
		require.Equal(t, "body", cl.GetItem().GetAttributes().GetFields()["http_request_body"].GetStringValue())

		// Cannot unset POST method (defaulting to GET) when request body is set
		_, err = s.UpdateCredentialLibrary(ctx, &pbs.UpdateCredentialLibraryRequest{
			Id:         vl.GetPublicId(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{httpMethodField}},
			Item: &pb.CredentialLibrary{
				Version: cl.GetItem().GetVersion(),
			},
		})
		require.Error(t, err)

		// Can clear request body and method (defaulting to GET) in the same request
		cl, err = s.UpdateCredentialLibrary(ctx, &pbs.UpdateCredentialLibraryRequest{
			Id:         vl.GetPublicId(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{httpMethodField, httpRequestBodyField}},
			Item: &pb.CredentialLibrary{
				Version: cl.GetItem().GetVersion(),
			},
		})
		assert.NoError(t, err)
		require.NotNil(t, cl)
		assert.Equal(t, "GET", cl.GetItem().GetAttributes().GetFields()["http_method"].GetStringValue())
		assert.Nil(t, cl.GetItem().GetAttributes().GetFields()["http_request_body"])
	})
}
