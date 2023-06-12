// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentiallibraries

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
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
	ctx := context.Background()
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
		return vault.NewRepository(ctx, rw, rw, kms, sche)
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
			Type:              vault.GenericLibrarySubtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
				VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
					Path:       wrapperspb.String(l.GetVaultPath()),
					HttpMethod: wrapperspb.String(l.GetHttpMethod()),
				},
			},
		})
	}
	for _, l := range vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 10) {
		wantLibraries = append(wantLibraries, &pb.CredentialLibrary{
			Id:                l.GetPublicId(),
			CredentialStoreId: l.GetStoreId(),
			CredentialType:    l.GetCredentialType(),
			Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
			CreatedTime:       l.GetCreateTime().GetTimestamp(),
			UpdatedTime:       l.GetUpdateTime().GetTimestamp(),
			Version:           l.GetVersion(),
			Type:              vault.SSHCertificateLibrarySubtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
				VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
					KeyType:  wrapperspb.String(l.GetKeyType()),
					Path:     wrapperspb.String(l.GetVaultPath()),
					Username: wrapperspb.String(l.GetUsername()),
				},
			},
		})
	}
	cases := []struct {
		name    string
		req     *pbs.ListCredentialLibrariesRequest
		res     *pbs.ListCredentialLibrariesResponse
		anonRes *pbs.ListCredentialLibrariesResponse
		err     error
	}{
		{
			name:    "List Many Libraries",
			req:     &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId()},
			res:     &pbs.ListCredentialLibrariesResponse{Items: wantLibraries},
			anonRes: &pbs.ListCredentialLibrariesResponse{Items: wantLibraries},
		},
		{
			name:    "List No Libraries",
			req:     &pbs.ListCredentialLibrariesRequest{CredentialStoreId: storeNoLibs.GetPublicId()},
			res:     &pbs.ListCredentialLibrariesResponse{},
			anonRes: &pbs.ListCredentialLibrariesResponse{},
		},
		{
			name:    "Filter to One Libraries",
			req:     &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantLibraries[1].GetId())},
			res:     &pbs.ListCredentialLibrariesResponse{Items: wantLibraries[1:2]},
			anonRes: &pbs.ListCredentialLibrariesResponse{Items: wantLibraries[1:2]},
		},
		{
			name:    "Filter to No Libraries",
			req:     &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:     &pbs.ListCredentialLibrariesResponse{},
			anonRes: &pbs.ListCredentialLibrariesResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListCredentialLibrariesRequest{CredentialStoreId: store.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(ctx, repoFn, iamRepoFn)
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
			got, gErr = s.ListCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(t, gErr)
			assert.Len(t, got.Items, len(tc.anonRes.Items))
			for _, item := range got.GetItems() {
				require.Nil(t, item.CreatedTime)
				require.Nil(t, item.UpdatedTime)
				require.Zero(t, item.Version)
			}
		})
	}
}

func TestList_Attributes(t *testing.T) {
	ctx := context.Background()
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
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}
	_, prj := iam.TestScopes(t, iamRepo)

	ts := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)
	storeGeneric, storeSSHCertificate := ts[0], ts[1]
	var wantLibrariesGeneric []*pb.CredentialLibrary
	var wantLibrariesSSHCertificate []*pb.CredentialLibrary
	for _, l := range vault.TestCredentialLibraries(t, conn, wrapper, storeGeneric.GetPublicId(), 5) {
		wantLibrariesGeneric = append(wantLibrariesGeneric, &pb.CredentialLibrary{
			Id:                l.GetPublicId(),
			CredentialStoreId: l.GetStoreId(),
			Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
			CreatedTime:       l.GetCreateTime().GetTimestamp(),
			UpdatedTime:       l.GetUpdateTime().GetTimestamp(),
			Version:           l.GetVersion(),
			Type:              vault.GenericLibrarySubtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
				VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
					Path:       wrapperspb.String(l.GetVaultPath()),
					HttpMethod: wrapperspb.String(l.GetHttpMethod()),
				},
			},
		})
	}
	for _, l := range vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, storeSSHCertificate.GetPublicId(), 10) {
		wantLibrariesSSHCertificate = append(wantLibrariesSSHCertificate, &pb.CredentialLibrary{
			Id:                l.GetPublicId(),
			CredentialStoreId: l.GetStoreId(),
			CredentialType:    l.GetCredentialType(),
			Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
			CreatedTime:       l.GetCreateTime().GetTimestamp(),
			UpdatedTime:       l.GetUpdateTime().GetTimestamp(),
			Version:           l.GetVersion(),
			Type:              vault.SSHCertificateLibrarySubtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
				VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
					KeyType:  wrapperspb.String(l.GetKeyType()),
					Path:     wrapperspb.String(l.GetVaultPath()),
					Username: wrapperspb.String(l.GetUsername()),
				},
			},
		})
	}
	cases := []struct {
		name    string
		req     *pbs.ListCredentialLibrariesRequest
		res     *pbs.ListCredentialLibrariesResponse
		anonRes *pbs.ListCredentialLibrariesResponse
		err     error
	}{
		{
			name:    "Filter on Attribute Generic Library",
			req:     &pbs.ListCredentialLibrariesRequest{CredentialStoreId: storeGeneric.GetPublicId(), Filter: fmt.Sprintf(`"/item/attributes/path"==%q`, wantLibrariesGeneric[2].GetVaultGenericCredentialLibraryAttributes().GetPath().Value)},
			res:     &pbs.ListCredentialLibrariesResponse{Items: wantLibrariesGeneric[2:3]},
			anonRes: &pbs.ListCredentialLibrariesResponse{}, // anonymous user does not have access to attributes
		},
		{
			name:    "Filter on Attribute SSH Certificate Library",
			req:     &pbs.ListCredentialLibrariesRequest{CredentialStoreId: storeSSHCertificate.GetPublicId(), Filter: fmt.Sprintf(`"/item/attributes/path"==%q`, wantLibrariesSSHCertificate[2].GetVaultSshCertificateCredentialLibraryAttributes().GetPath().Value)},
			res:     &pbs.ListCredentialLibrariesResponse{Items: wantLibrariesSSHCertificate[2:3]},
			anonRes: &pbs.ListCredentialLibrariesResponse{}, // anonymous user does not have access to attributes
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(ctx, repoFn, iamRepoFn)
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
			got, gErr = s.ListCredentialLibraries(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(t, gErr)
			assert.Len(t, got.Items, len(tc.anonRes.Items))
			for _, item := range got.GetItems() {
				require.Nil(t, item.CreatedTime)
				require.Nil(t, item.UpdatedTime)
				require.Zero(t, item.Version)
			}
		})
	}
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
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
		return vault.NewRepository(ctx, rw, rw, kms, sche)
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
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{},
				},
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			wantErr:  true,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Id:                globals.VaultCredentialLibraryPrefix + "_notallowed",
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				CreatedTime:       timestamppb.Now(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				UpdatedTime:       timestamppb.Now(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Type and parent id must match",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              "static",
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "parent id must be included",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				Type: vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cannot specify a http request body when http method is get",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path:            wrapperspb.String("something"),
						HttpRequestBody: wrapperspb.String("foo"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid Method",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path:       wrapperspb.String("something"),
						HttpMethod: wrapperspb.String("PATCH"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Request Body With GET Method",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path:            wrapperspb.String("something"),
						HttpRequestBody: wrapperspb.String("foo"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid credential type",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
				CredentialType: "fake-type",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid username_password mapping",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
				CredentialType: string(credential.UsernamePasswordType),
				CredentialMappingOverrides: func() *structpb.Struct {
					v := map[string]any{
						usernameAttribute: "user-test",
						"invalid":         "invalid-test",
					}
					ret, err := structpb.NewStruct(v)
					require.NoError(t, err)
					return ret
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Using POST method",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path:            wrapperspb.String("something"),
						HttpMethod:      wrapperspb.String("post"),
						HttpRequestBody: wrapperspb.String("foo"),
					},
				},
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:            wrapperspb.String("something"),
							HttpMethod:      wrapperspb.String("POST"),
							HttpRequestBody: wrapperspb.String("foo"),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Name:              &wrapperspb.StringValue{Value: "name"},
				Description:       &wrapperspb.StringValue{Value: "desc"},
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary username_password type",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
				CredentialType: string(credential.UsernamePasswordType),
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					CredentialType:    string(credential.UsernamePasswordType),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary username_password type with username mapping",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
				CredentialMappingOverrides: func() *structpb.Struct {
					v := map[string]any{
						usernameAttribute: "user-test",
					}
					ret, err := structpb.NewStruct(v)
					require.NoError(t, err)
					return ret
				}(),
				CredentialType: string(credential.UsernamePasswordType),
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					CredentialType: string(credential.UsernamePasswordType),
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: "user-test",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary username_password type with username/password mapping",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
				CredentialMappingOverrides: func() *structpb.Struct {
					v := map[string]any{
						usernameAttribute: "user-test",
						passwordAttribute: "pass-test",
					}
					ret, err := structpb.NewStruct(v)
					require.NoError(t, err)
					return ret
				}(),
				CredentialType: string(credential.UsernamePasswordType),
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					CredentialType: string(credential.UsernamePasswordType),
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: "user-test",
							passwordAttribute: "pass-test",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary ssh_private_key type",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
				CredentialType: string(credential.SshPrivateKeyType),
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					CredentialType:    string(credential.SshPrivateKeyType),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary ssh_private_key type with mapping",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.GenericLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
				CredentialMappingOverrides: func() *structpb.Struct {
					v := map[string]any{
						usernameAttribute:     "user-test",
						privateKeyAttribute:   "pk-test",
						pkPassphraseAttribute: "pass-test",
					}
					ret, err := structpb.NewStruct(v)
					require.NoError(t, err)
					return ret
				}(),
				CredentialType: string(credential.SshPrivateKeyType),
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					CredentialType: string(credential.SshPrivateKeyType),
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute:     "user-test",
							privateKeyAttribute:   "pk-test",
							pkPassphraseAttribute: "pass-test",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary with the 'vault' subtype",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.Subtype.String(),
				Attrs: &pb.CredentialLibrary_VaultCredentialLibraryAttributes{
					VaultCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialLibrary with no type set subtype",
			req: &pbs.CreateCredentialLibraryRequest{
				Item: &pb.CredentialLibrary{
					CredentialStoreId: store.GetPublicId(),
					Type:              "",
					Attrs: &pb.CredentialLibrary_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"path": structpb.NewStringValue("something"),
							},
						},
					},
				},
			},
			idPrefix: globals.VaultCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.GenericLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String("something"),
							HttpMethod: wrapperspb.String("GET"),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(ctx, repoFn, iamRepoFn)
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
	ctx := context.Background()
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
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)

	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	unspecifiedLib := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
	s, err := NewService(ctx, repoFn, iamRepoFn)
	require.NoError(t, err)

	repo, err := repoFn()
	require.NoError(t, err)

	lib, err := vault.NewCredentialLibrary(store.GetPublicId(), "vault/path",
		vault.WithCredentialType("username_password"),
		vault.WithMappingOverride(
			vault.NewUsernamePasswordOverride(
				vault.WithOverrideUsernameAttribute("user"),
				vault.WithOverridePasswordAttribute("pass"),
			)))
	require.NoError(t, err)
	userPassLib, err := repo.CreateCredentialLibrary(context.Background(), prj.GetPublicId(), lib)
	require.NoError(t, err)

	lib1, err := vault.NewCredentialLibrary(store.GetPublicId(), "vault/path/ssh",
		vault.WithCredentialType("ssh_private_key"),
		vault.WithMappingOverride(
			vault.NewSshPrivateKeyOverride(
				vault.WithOverrideUsernameAttribute("user"),
				vault.WithOverridePrivateKeyAttribute("pk"),
				vault.WithOverridePrivateKeyPassphraseAttribute("pass"),
			)))
	require.NoError(t, err)
	sshPkLib, err := repo.CreateCredentialLibrary(context.Background(), prj.GetPublicId(), lib1)
	require.NoError(t, err)

	lib2, err := vault.NewSSHCertificateCredentialLibrary(store.GetPublicId(), "/ssh/sign/foo", "username")
	require.NoError(t, err)
	sshCertLib, err := repo.CreateSSHCertificateCredentialLibrary(context.Background(), prj.GetPublicId(), lib2)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		res  *pbs.GetCredentialLibraryResponse
		err  error
	}{
		{
			name: "success",
			id:   unspecifiedLib.GetPublicId(),
			res: &pbs.GetCredentialLibraryResponse{
				Item: &pb.CredentialLibrary{
					Id:                unspecifiedLib.GetPublicId(),
					CredentialStoreId: unspecifiedLib.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              vault.GenericLibrarySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       unspecifiedLib.CreateTime.GetTimestamp(),
					UpdatedTime:       unspecifiedLib.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String(unspecifiedLib.GetVaultPath()),
							HttpMethod: wrapperspb.String(unspecifiedLib.GetHttpMethod()),
						},
					},
				},
			},
		},
		{
			name: "success-UsernamePassword",
			id:   userPassLib.GetPublicId(),
			res: &pbs.GetCredentialLibraryResponse{
				Item: &pb.CredentialLibrary{
					Id:                userPassLib.GetPublicId(),
					CredentialStoreId: userPassLib.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              vault.GenericLibrarySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       userPassLib.CreateTime.GetTimestamp(),
					UpdatedTime:       userPassLib.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String(userPassLib.GetVaultPath()),
							HttpMethod: wrapperspb.String(userPassLib.GetHttpMethod()),
						},
					},
					CredentialType: "username_password",
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: "user",
							passwordAttribute: "pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
		},
		{
			name: "success-ssh-private-key",
			id:   sshPkLib.GetPublicId(),
			res: &pbs.GetCredentialLibraryResponse{
				Item: &pb.CredentialLibrary{
					Id:                sshPkLib.GetPublicId(),
					CredentialStoreId: sshPkLib.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              vault.GenericLibrarySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       sshPkLib.CreateTime.GetTimestamp(),
					UpdatedTime:       sshPkLib.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:       wrapperspb.String(sshPkLib.GetVaultPath()),
							HttpMethod: wrapperspb.String(sshPkLib.GetHttpMethod()),
						},
					},
					CredentialType: "ssh_private_key",
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute:     "user",
							privateKeyAttribute:   "pk",
							pkPassphraseAttribute: "pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
		},
		{
			name: "success-ssh-certificate",
			id:   sshCertLib.GetPublicId(),
			res: &pbs.GetCredentialLibraryResponse{
				Item: &pb.CredentialLibrary{
					Id:                sshCertLib.GetPublicId(),
					CredentialStoreId: sshCertLib.GetStoreId(),
					CredentialType:    sshCertLib.GetCredentialType(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              vault.SSHCertificateLibrarySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       sshCertLib.CreateTime.GetTimestamp(),
					UpdatedTime:       sshCertLib.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							KeyType:  wrapperspb.String(sshCertLib.GetKeyType()),
							Path:     wrapperspb.String(sshCertLib.GetVaultPath()),
							Username: wrapperspb.String(sshCertLib.GetUsername()),
						},
					},
				},
			},
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.VaultCredentialLibraryPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticHostPrefix),
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
			got, gErr = s.GetCredentialLibrary(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), req)
			require.NoError(t, gErr)
			require.Nil(t, got.Item.CreatedTime)
			require.Nil(t, got.Item.UpdatedTime)
			require.Zero(t, got.Item.Version)
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
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
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)

	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	vl := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
	vl2 := vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
	s, err := NewService(ctx, repoFn, iamRepoFn)
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
		},
		{
			name: "success-ssh-cert",
			id:   vl2.GetPublicId(),
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.VaultCredentialLibraryPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticHostPrefix),
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
	testCtx := context.Background()
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
		return vault.NewRepository(testCtx, rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())

	s, err := NewService(testCtx, repoFn, iamRepoFn)
	require.NoError(t, err)
	cs := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)
	store, diffStore := cs[0], cs[1]

	freshLibrary := func(opt ...vault.Option) (*vault.CredentialLibrary, func()) {
		repo, err := repoFn()
		require.NoError(t, err)
		lib, err := vault.NewCredentialLibrary(store.GetPublicId(), "vault/path", opt...)
		require.NoError(t, err)

		vl, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), lib)
		require.NoError(t, err)
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

	usernameAttrField := fmt.Sprintf("%v.%v", credentialMappingPathField, usernameAttribute)
	passwordAttrField := fmt.Sprintf("%v.%v", credentialMappingPathField, passwordAttribute)
	privateKeyAttrField := fmt.Sprintf("%v.%v", credentialMappingPathField, privateKeyAttribute)
	passphraseAttrField := fmt.Sprintf("%v.%v", credentialMappingPathField, pkPassphraseAttribute)

	successCases := []struct {
		name string
		opts []vault.Option
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
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							HttpMethod: wrapperspb.String("pOsT"),
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultGenericCredentialLibraryAttributes().Path = wrapperspb.String("vault/path")
				out.GetVaultGenericCredentialLibraryAttributes().HttpMethod = wrapperspb.String("POST")
				return out
			},
		},
		{
			name: "update request body and method",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(httpRequestBodyField, httpMethodField),
				Item: &pb.CredentialLibrary{
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							HttpMethod:      wrapperspb.String("pOsT"),
							HttpRequestBody: wrapperspb.String("body"),
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultGenericCredentialLibraryAttributes().Path = wrapperspb.String("vault/path")
				out.GetVaultGenericCredentialLibraryAttributes().HttpMethod = wrapperspb.String("POST")
				out.GetVaultGenericCredentialLibraryAttributes().HttpRequestBody = wrapperspb.String("body")
				return out
			},
		},
		{
			name: "update path",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(vaultPathField),
				Item: &pb.CredentialLibrary{
					Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
						VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path: wrapperspb.String("something"),
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultGenericCredentialLibraryAttributes().Path = wrapperspb.String("something")
				return out
			},
		},
		{
			name: "username-password-attributes-change-username-attribute",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
				vault.WithMappingOverride(
					vault.NewUsernamePasswordOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePasswordAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(usernameAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: "changed-user",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides.Fields[usernameAttribute] = structpb.NewStringValue("changed-user")
				return out
			},
		},
		{
			name: "username-password-attributes-change-password-attribute",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
				vault.WithMappingOverride(
					vault.NewUsernamePasswordOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePasswordAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(passwordAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							passwordAttribute: "changed-pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides.Fields[passwordAttribute] = structpb.NewStringValue("changed-pass")
				return out
			},
		},
		{
			name: "username-password-attributes-change-username-and-password-attributes",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
				vault.WithMappingOverride(
					vault.NewUsernamePasswordOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePasswordAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(passwordAttrField, usernameAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: "changed-user",
							passwordAttribute: "changed-pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides.Fields[usernameAttribute] = structpb.NewStringValue("changed-user")
				out.CredentialMappingOverrides.Fields[passwordAttribute] = structpb.NewStringValue("changed-pass")
				return out
			},
		},
		{
			name: "no-mapping-override-change-username-and-password-attributes",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(passwordAttrField, usernameAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: "new-user",
							passwordAttribute: "new-pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				v := map[string]any{
					usernameAttribute: "new-user",
					passwordAttribute: "new-pass",
				}
				var err error
				out.CredentialMappingOverrides, err = structpb.NewStruct(v)
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "username-password-attributes-delete-mapping-override",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
				vault.WithMappingOverride(
					vault.NewUsernamePasswordOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePasswordAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(credentialMappingPathField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: nil,
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
		{
			name: "no-mapping-override-delete-mapping-override",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(credentialMappingPathField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: nil,
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
		{
			name: "username-password-attributes-delete-mapping-override-field-specific",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
				vault.WithMappingOverride(
					vault.NewUsernamePasswordOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePasswordAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(passwordAttrField, usernameAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: nil,
							passwordAttribute: nil,
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
		{
			name: "no-mapping-override-delete-mapping-override-field-specific",
			opts: []vault.Option{
				vault.WithCredentialType("username_password"),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(passwordAttrField, usernameAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: nil,
							passwordAttribute: nil,
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
		{
			name: "ssh-private-key-attributes-change-username-attribute",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
				vault.WithMappingOverride(
					vault.NewSshPrivateKeyOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePrivateKeyAttribute("orig-pk"),
						vault.WithOverridePrivateKeyPassphraseAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(usernameAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute: "changed-user",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides.Fields[usernameAttribute] = structpb.NewStringValue("changed-user")
				return out
			},
		},
		{
			name: "ssh-private-key-attributes-change-private-key-attribute",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
				vault.WithMappingOverride(
					vault.NewSshPrivateKeyOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePrivateKeyAttribute("orig-pk"),
						vault.WithOverridePrivateKeyPassphraseAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(privateKeyAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							privateKeyAttribute: "changed-pk",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides.Fields[privateKeyAttribute] = structpb.NewStringValue("changed-pk")
				return out
			},
		},
		{
			name: "ssh-private-key-attributes-change-passphrase-attribute",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
				vault.WithMappingOverride(
					vault.NewSshPrivateKeyOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePrivateKeyAttribute("orig-pk"),
						vault.WithOverridePrivateKeyPassphraseAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(passphraseAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							pkPassphraseAttribute: "changed-pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides.Fields[pkPassphraseAttribute] = structpb.NewStringValue("changed-pass")
				return out
			},
		},
		{
			name: "ssh-private-key-attributes-change-all-attributes",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
				vault.WithMappingOverride(
					vault.NewSshPrivateKeyOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePrivateKeyAttribute("orig-pk"),
						vault.WithOverridePrivateKeyPassphraseAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(privateKeyAttrField, usernameAttrField, passphraseAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute:     "changed-user",
							privateKeyAttribute:   "changed-pk",
							pkPassphraseAttribute: "changed-pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides.Fields[usernameAttribute] = structpb.NewStringValue("changed-user")
				out.CredentialMappingOverrides.Fields[privateKeyAttribute] = structpb.NewStringValue("changed-pk")
				out.CredentialMappingOverrides.Fields[pkPassphraseAttribute] = structpb.NewStringValue("changed-pass")
				return out
			},
		},
		{
			name: "no-mapping-override-change-all-attributes",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(privateKeyAttrField, usernameAttrField, passphraseAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute:     "new-user",
							privateKeyAttribute:   "new-pk",
							pkPassphraseAttribute: "new-pass",
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				v := map[string]any{
					usernameAttribute:     "new-user",
					privateKeyAttribute:   "new-pk",
					pkPassphraseAttribute: "new-pass",
				}
				var err error
				out.CredentialMappingOverrides, err = structpb.NewStruct(v)
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "ssh-private-key-attributes-delete-mapping-override",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
				vault.WithMappingOverride(
					vault.NewSshPrivateKeyOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePrivateKeyAttribute("orig-pk"),
						vault.WithOverridePrivateKeyPassphraseAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(credentialMappingPathField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: nil,
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
		{
			name: "ssh-private-key-no-mapping-override-delete-mapping-override",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(credentialMappingPathField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: nil,
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
		{
			name: "ssh-private-key-attributes-delete-mapping-override-field-specific",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
				vault.WithMappingOverride(
					vault.NewSshPrivateKeyOverride(
						vault.WithOverrideUsernameAttribute("orig-user"),
						vault.WithOverridePrivateKeyAttribute("orig-pk"),
						vault.WithOverridePrivateKeyPassphraseAttribute("orig-pass"),
					)),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(privateKeyAttrField, usernameAttrField, passphraseAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute:     nil,
							privateKeyAttribute:   nil,
							pkPassphraseAttribute: nil,
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
		{
			name: "ssh-private-key-no-mapping-override-delete-mapping-override-field-specific",
			opts: []vault.Option{
				vault.WithCredentialType("ssh_private_key"),
			},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(privateKeyAttrField, usernameAttrField),
				Item: &pb.CredentialLibrary{
					CredentialMappingOverrides: func() *structpb.Struct {
						v := map[string]any{
							usernameAttribute:   nil,
							privateKeyAttribute: nil,
						}
						ret, err := structpb.NewStruct(v)
						require.NoError(t, err)
						return ret
					}(),
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.CredentialMappingOverrides = nil
				return out
			},
		},
	}

	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			st, cleanup := freshLibrary(tc.opts...)
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
		{
			name: "read only credential type",
			path: "credential_type",
			item: &pb.CredentialLibrary{CredentialType: string(credential.UsernamePasswordType)},
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
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						HttpRequestBody: wrapperspb.String("body"),
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
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						HttpMethod: wrapperspb.String("POST"),
					},
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, cl)
		require.Equal(t, "POST", cl.GetItem().GetVaultGenericCredentialLibraryAttributes().GetHttpMethod().Value)

		// Can set request body on POST
		cl, err = s.UpdateCredentialLibrary(ctx, &pbs.UpdateCredentialLibraryRequest{
			Id:         vl.GetPublicId(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{httpRequestBodyField}},
			Item: &pb.CredentialLibrary{
				Version: cl.Item.GetVersion(),
				Attrs: &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
					VaultGenericCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
						HttpRequestBody: wrapperspb.String("body"),
					},
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, cl)
		require.Equal(t, "POST", cl.GetItem().GetVaultGenericCredentialLibraryAttributes().GetHttpMethod().Value)
		require.Equal(t, "body", cl.GetItem().GetVaultGenericCredentialLibraryAttributes().GetHttpRequestBody().Value)

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
		assert.Equal(t, "GET", cl.GetItem().GetVaultGenericCredentialLibraryAttributes().GetHttpMethod().Value)
		assert.Nil(t, cl.GetItem().GetVaultGenericCredentialLibraryAttributes().GetHttpRequestBody())
	})
}

func TestCreate_SSHCertificateCredentialLibrary(t *testing.T) {
	ctx := context.Background()
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
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	defaultCL := vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 1)[0]
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
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Username: wrapperspb.String("username"),
					},
				},
			}},
			idPrefix: globals.VaultSshCertificateCredentialLibraryPrefix + "_",
			wantErr:  true,
		},
		{
			name: "missing username",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path: wrapperspb.String("something"),
					},
				},
			}},
			idPrefix: globals.VaultSshCertificateCredentialLibraryPrefix + "_",
			wantErr:  true,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				Id:                globals.VaultSshCertificateCredentialLibraryPrefix + "_notallowed",
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("something"),
						Username: wrapperspb.String("username"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				CreatedTime:       timestamppb.Now(),
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("something"),
						Username: wrapperspb.String("username"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				UpdatedTime:       timestamppb.Now(),
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("something"),
						Username: wrapperspb.String("username"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Type and parent id must match",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              "static",
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("something"),
						Username: wrapperspb.String("username"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "parent id must be included",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				Type: vault.SSHCertificateLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("something"),
						Username: wrapperspb.String("username"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid credential type",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("something"),
						Username: wrapperspb.String("username"),
					},
				},
				CredentialType: "fake-type",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid key type key bits combination",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("something"),
						Username: wrapperspb.String("username"),
						KeyType:  wrapperspb.String(vault.KeyTypeEd25519),
						KeyBits:  wrapperspb.UInt32(256),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create a valid vault SSHCertificateCredentialLibrary",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				Name:              &wrapperspb.StringValue{Value: "name"},
				Description:       &wrapperspb.StringValue{Value: "desc"},
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("/ssh/sign/foo"),
						Username: wrapperspb.String("username"),
					},
				},
			}},
			idPrefix: globals.VaultSshCertificateCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultSshCertificateCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							Path:     wrapperspb.String("/ssh/sign/foo"),
							Username: wrapperspb.String("username"),
							KeyType:  wrapperspb.String(vault.KeyTypeEd25519),
						},
					},
					AuthorizedActions: testAuthorizedActions,
					CredentialType:    string(credential.SshCertificateType),
				},
			},
		},
		{
			name: "Seting key type ed25119 with key bits nil",
			req: &pbs.CreateCredentialLibraryRequest{Item: &pb.CredentialLibrary{
				CredentialStoreId: store.GetPublicId(),
				Type:              vault.SSHCertificateLibrarySubtype.String(),
				Name:              &wrapperspb.StringValue{Value: "name2"},
				Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
					VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
						Path:     wrapperspb.String("/ssh/sign/foo"),
						Username: wrapperspb.String("username"),
						KeyType:  wrapperspb.String(vault.KeyTypeEd25519),
					},
				},
			}},
			idPrefix: globals.VaultSshCertificateCredentialLibraryPrefix + "_",
			res: &pbs.CreateCredentialLibraryResponse{
				Uri: fmt.Sprintf("credential-libraries/%s_", globals.VaultSshCertificateCredentialLibraryPrefix),
				Item: &pb.CredentialLibrary{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Name:              &wrapperspb.StringValue{Value: "name2"},
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							Path:     wrapperspb.String("/ssh/sign/foo"),
							Username: wrapperspb.String("username"),
							KeyType:  wrapperspb.String(vault.KeyTypeEd25519),
						},
					},
					AuthorizedActions: testAuthorizedActions,
					CredentialType:    string(credential.SshCertificateType),
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(ctx, repoFn, iamRepoFn)
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

func TestUpdate_SSHCertificateCredentialLibrary(t *testing.T) {
	testCtx := context.Background()
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
		return vault.NewRepository(testCtx, rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())

	s, err := NewService(testCtx, repoFn, iamRepoFn)
	require.NoError(t, err)
	cs := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)
	store, diffStore := cs[0], cs[1]

	freshLibrary := func(opt ...vault.Option) (*vault.SSHCertificateCredentialLibrary, func()) {
		repo, err := repoFn()
		require.NoError(t, err)
		lib, err := vault.NewSSHCertificateCredentialLibrary(store.GetPublicId(), "/ssh/sign/foo", "username", opt...)
		require.NoError(t, err)

		vl, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), lib)
		require.NoError(t, err)
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

	testExtensionBytes, _ := json.Marshal(map[string]string{"permit-pty": ""})
	testCriticalOptionsBytes, _ := json.Marshal(map[string]string{"option-a": "set-a"})

	successCases := []struct {
		name string
		opts []vault.Option
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
			name: "update username",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(sshCertUsernameField),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							Username: wrapperspb.String("changed-username"),
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultSshCertificateCredentialLibraryAttributes().Username = wrapperspb.String("changed-username")
				return out
			},
		},
		{
			name: "update key type and key bits",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask("attributes.key_type", "attributes.key_bits"),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							KeyType: wrapperspb.String(vault.KeyTypeRsa),
							KeyBits: wrapperspb.UInt32(2048),
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultSshCertificateCredentialLibraryAttributes().KeyType = wrapperspb.String("rsa")
				out.GetVaultSshCertificateCredentialLibraryAttributes().KeyBits = wrapperspb.UInt32(2048)
				return out
			},
		},
		{
			name: "update path",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(vaultPathField),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							Path: wrapperspb.String("/ssh/issue/foo"),
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultSshCertificateCredentialLibraryAttributes().Path = wrapperspb.String("/ssh/issue/foo")
				return out
			},
		},
		{
			name: "update other attr fields",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask("attributes.ttl", "attributes.key_id", "attributes.critical_options.some", "attributes.extensions.permity-pty"),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							KeyId:           wrapperspb.String("id"),
							CriticalOptions: map[string]string{"some": "option"},
							Extensions:      map[string]string{"permit-pty": ""},
							Ttl:             wrapperspb.String("2m"),
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultSshCertificateCredentialLibraryAttributes().Ttl = wrapperspb.String("2m")
				out.GetVaultSshCertificateCredentialLibraryAttributes().KeyId = wrapperspb.String("id")
				out.GetVaultSshCertificateCredentialLibraryAttributes().CriticalOptions = map[string]string{"some": "option"}
				out.GetVaultSshCertificateCredentialLibraryAttributes().Extensions = map[string]string{"permit-pty": ""}
				return out
			},
		},
		{
			name: "clear critical options, extensions fields",
			opts: []vault.Option{vault.WithExtensions(string(testExtensionBytes)), vault.WithCriticalOptions(string(testCriticalOptionsBytes))},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask("attributes.critical_options", "attributes.extensions.permit-pty"),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							CriticalOptions: nil,
							Extensions:      nil,
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultSshCertificateCredentialLibraryAttributes().CriticalOptions = nil
				out.GetVaultSshCertificateCredentialLibraryAttributes().Extensions = nil
				return out
			},
		},
		{
			name: "set critical options while clearing extensions",
			opts: []vault.Option{vault.WithExtensions(string(testExtensionBytes)), vault.WithCriticalOptions(string(testCriticalOptionsBytes))},
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask("attributes.critical_options.option-b", "attributes.extensions"),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							CriticalOptions: map[string]string{"option-b": "set-b"},
							Extensions:      nil,
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultSshCertificateCredentialLibraryAttributes().CriticalOptions = map[string]string{"option-b": "set-b"}
				out.GetVaultSshCertificateCredentialLibraryAttributes().Extensions = nil
				return out
			},
		},
		{
			name: "set multiple critical options, extensions",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask("attributes.critical_options.option-a", "attributes.critical_options.option-b", "attributes.critical_options.option-c",
					"attributes.extensions.permit-pty", "attributes.extensions.permit-port-forwarding", "attributes.extensions.permit-X11-forwarding"),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							CriticalOptions: map[string]string{"option-a": "set-a", "option-b": "set-b", "option-c": "set-c"},
							Extensions:      map[string]string{"permit-pty": "", "permit-port-forwarding": "", "permit-X11-forwarding": ""},
						},
					},
				},
			},
			res: func(in *pb.CredentialLibrary) *pb.CredentialLibrary {
				out := proto.Clone(in).(*pb.CredentialLibrary)
				out.GetVaultSshCertificateCredentialLibraryAttributes().CriticalOptions = map[string]string{"option-a": "set-a", "option-b": "set-b", "option-c": "set-c"}
				out.GetVaultSshCertificateCredentialLibraryAttributes().Extensions = map[string]string{"permit-pty": "", "permit-port-forwarding": "", "permit-X11-forwarding": ""}
				return out
			},
		},
	}

	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			st, cleanup := freshLibrary(tc.opts...)
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
		{
			name: "read only credential type",
			path: "credential_type",
			item: &pb.CredentialLibrary{CredentialType: string(credential.UsernamePasswordType)},
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
	vErrs := []struct {
		name        string
		req         *pbs.UpdateCredentialLibraryRequest
		errContains string
	}{
		{
			name: "invalid key type key bits combination",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(keyBitsField, keyTypeField),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							KeyType: wrapperspb.String(vault.KeyTypeEcdsa),
							KeyBits: wrapperspb.UInt32(2048),
						},
					},
				},
			},
			errContains: "Invalid bit size 2048 for key type ecdsa",
		},
		{
			name: "invalid key type",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(keyTypeField),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							KeyType: wrapperspb.String("unknown-type"),
						},
					},
				},
			},
			errContains: "If set, value must be 'ed25519', 'ecdsa', or 'rsa'.",
		},
		{
			name: "invalid key bits",
			req: &pbs.UpdateCredentialLibraryRequest{
				UpdateMask: fieldmask(keyBitsField),
				Item: &pb.CredentialLibrary{
					Type: vault.SSHCertificateLibrarySubtype.String(),
					Attrs: &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
						VaultSshCertificateCredentialLibraryAttributes: &pb.VaultSSHCertificateCredentialLibraryAttributes{
							KeyBits: wrapperspb.UInt32(1234),
						},
					},
				},
			},
			errContains: "Invalid bit size 1234",
		},
	}
	for _, tc := range vErrs {
		t.Run(tc.name, func(t *testing.T) {
			scl, cleanup := freshLibrary()
			defer cleanup()

			if tc.req.Item.GetVersion() == 0 {
				tc.req.Item.Version = 1
			}
			if tc.req.GetId() == "" {
				tc.req.Id = scl.GetPublicId()
			}
			got, gErr := s.UpdateCredentialLibrary(ctx, tc.req)
			if gErr != nil {
				assert.Contains(t, gErr.Error(), tc.errContains)
				assert.Nil(t, got)
			}
		})
	}
}
