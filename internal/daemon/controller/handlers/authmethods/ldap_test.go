// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	am "github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func Test_UpdateLdap(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	tested, err := authmethods.NewService(ctx, kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}

	defaultAttributes := &pb.AuthMethod_LdapAuthMethodsAttributes{
		LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
			Urls:  []string{"ldaps://ldap1"},
			State: "active-private",
		},
	}
	defaultReadAttributes := &pb.AuthMethod_LdapAuthMethodsAttributes{
		LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
			Urls:  []string{"ldaps://ldap1"},
			State: "active-private",
		},
	}

	freshAuthMethod := func(t *testing.T, attrs *pb.AuthMethod_LdapAuthMethodsAttributes) (*pb.AuthMethod, func()) {
		if attrs == nil {
			attrs = defaultAttributes
		}
		ctx := auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId())
		am, err := tested.CreateAuthMethod(ctx, &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
			ScopeId:     o.GetPublicId(),
			Name:        wrapperspb.String("default"),
			Description: wrapperspb.String("default"),
			Type:        ldap.Subtype.String(),
			Attrs:       attrs,
		}})
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteAuthMethodRequest{Id: am.GetItem().GetId()})
			require.NoError(t, err)
		}
		return am.GetItem(), clean
	}

	_, testEncodedCert := ldap.TestGenerateCA(t, "localhost")

	tests := []struct {
		name             string
		newAttrsOverride *pb.AuthMethod_LdapAuthMethodsAttributes
		req              *pbs.UpdateAuthMethodRequest
		res              *pbs.UpdateAuthMethodResponse
		err              error
		errContains      string
		wantErr          bool
	}{
		{
			name: "update-an-existing-auth-method",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        ldap.Subtype.String(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Version:                     2,
					Type:                        ldap.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "multi-paths-in-single-string",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        ldap.Subtype.String(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Version:                     2,
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Type:                        ldap.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "no-update-mask",
			req: &pbs.UpdateAuthMethodRequest{
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "UpdateMask not provided but is required to update this resource",
		},
		{
			name: "missing-paths-in-mask",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask",
		},
		{
			name: "non-existent-paths-in-mask",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask",
		},
		{
			name: "cannot-change-type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"name", "type"}},
				Item: &pb.AuthMethod{
					Name: &wrapperspb.StringValue{Value: "updated name"},
					Type: password.Subtype.String(),
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Cannot modify the resource type",
		},
		{
			name: "cannot-change-is-primary",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"is_primary"}},
				Item: &pb.AuthMethod{
					IsPrimary: true,
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "This field is read only",
		},
		{
			name: "unset-name",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.AuthMethod{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Version:                     2,
					Description:                 &wrapperspb.StringValue{Value: "default"},
					Type:                        ldap.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "unset-description",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Version:                     2,
					Name:                        &wrapperspb.StringValue{Value: "default"},
					Type:                        ldap.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "update-only-state",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.state"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							State: "active-public",
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:  []string{"ldaps://ldap1"},
							State: "active-public",
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "update-only-name",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Version:                     2,
					Name:                        &wrapperspb.StringValue{Value: "updated"},
					Description:                 &wrapperspb.StringValue{Value: "default"},
					Type:                        ldap.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "update-only-description",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Version:                     2,
					Name:                        &wrapperspb.StringValue{Value: "default"},
					Description:                 &wrapperspb.StringValue{Value: "notignored"},
					Type:                        ldap.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "update-only-bind-dn",
			newAttrsOverride: &pb.AuthMethod_LdapAuthMethodsAttributes{
				LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
					Urls:         []string{"ldaps://ldap1"},
					State:        "active-private",
					BindDn:       &wrapperspb.StringValue{Value: "bind-dn"},
					BindPassword: &wrapperspb.StringValue{Value: "bind-password"},
				},
			},
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.bind_dn"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							BindDn: &wrapperspb.StringValue{Value: "updated"},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:   []string{"ldaps://ldap1"},
							State:  "active-private",
							BindDn: &wrapperspb.StringValue{Value: "updated"},
							// note: BindPassword is never returned (an HMAC'd
							// value is returned in a separate attribute)
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "err-update-only-bind-dn-with-no-orig-bind-password",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.bind_dn"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							BindDn: &wrapperspb.StringValue{Value: "updated"},
						},
					},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "missing password",
		},
		{
			name: "update-only-bind-password",
			newAttrsOverride: &pb.AuthMethod_LdapAuthMethodsAttributes{
				LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
					Urls:         []string{"ldaps://ldap1"},
					State:        "active-private",
					BindDn:       &wrapperspb.StringValue{Value: "bind-dn"},
					BindPassword: &wrapperspb.StringValue{Value: "bind-password"},
				},
			},
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.bind_password"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							BindPassword: &wrapperspb.StringValue{Value: "updated"},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:   []string{"ldaps://ldap1"},
							State:  "active-private",
							BindDn: &wrapperspb.StringValue{Value: "bind-dn"},
							// note: BindPassword is never returned (an HMAC'd
							// value is returned in a separate attribute)
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "err-update-only-bind-password-with-no-orig-bind-dn",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.bind_password"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							BindPassword: &wrapperspb.StringValue{Value: "updated"},
						},
					},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "missing dn",
		},
		{
			name: "update-a-non-existent-auth-method",
			req: &pbs.UpdateAuthMethodRequest{
				Id: globals.LdapAuthMethodPrefix + "_DoesNotExist",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found",
		},
		{
			name: "cannot-change-id",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.AuthMethod{
					Id:          globals.LdapAuthMethodPrefix + "_something",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "This is a read only field and cannot be specified in an update request",
		},
		{
			name: "cannot-specify-created-time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.AuthMethod{
					CreatedTime: timestamppb.Now(),
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "This is a read only field and cannot be specified in an update request",
		},
		{
			name: "cannot-specify-updated-time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.AuthMethod{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "This is a read only field and cannot be specified in an update request",
		},
		{
			name: "cannot-specify-type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.AuthMethod{
					Type: ldap.Subtype.String(),
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask",
		},
		{
			name: "cannot-change-scope",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"scope"},
				},
				Item: &pb.AuthMethod{
					ScopeId:     "something-new",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask",
		},
		{
			name: "invalid-certs",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.certificates"},
				},
				Item: &pb.AuthMethod{
					ScopeId: "something-new",
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Certificates: []string{ldap.TestInvalidPem},
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "invalid attributes.certificates",
		},
		{
			name: "update-certs",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.certificates"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Certificates: []string{testEncodedCert},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:         []string{"ldaps://ldap1"},
							State:        "active-private",
							Certificates: []string{testEncodedCert},
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "update-urls",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.urls"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls: []string{"ldaps://ldap2", "ldaps://ldap3"},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:  []string{"ldaps://ldap2", "ldaps://ldap3"},
							State: "active-private",
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "update-urls-err",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.urls"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls: []string{" ldaps://ldap2"}, // invalid url (space at start)
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "is not a valid url",
		},
		{
			name: "update-user-search-config",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.user_dn", "attributes.user_attr", "attributes.user_filter"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							UserDn:     wrapperspb.String("user-dn"),
							UserAttr:   wrapperspb.String("user-attr"),
							UserFilter: wrapperspb.String("user-filter"),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:       []string{"ldaps://ldap1"},
							State:      "active-private",
							UserDn:     wrapperspb.String("user-dn"),
							UserAttr:   wrapperspb.String("user-attr"),
							UserFilter: wrapperspb.String("user-filter"),
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "use-token-groups",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.use_token_groups"},
				},
				Item: &pb.AuthMethod{
					ScopeId: "something-new",
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							UseTokenGroups: true,
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:           []string{"ldaps://ldap1"},
							State:          "active-private",
							UseTokenGroups: true,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "enable-groups-err",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.enable_groups"},
				},
				Item: &pb.AuthMethod{
					ScopeId: "something-new",
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							EnableGroups: true,
						},
					},
				},
			},
			res:         nil,
			wantErr:     true,
			errContains: "have a configured group_dn when enable_groups = true and use_token_groups = false",
		},
		{
			name: "update-group-search-config",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.group_dn", "attributes.group_attr", "attributes.group_filter"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							GroupDn:     wrapperspb.String("group-dn"),
							GroupAttr:   wrapperspb.String("group-attr"),
							GroupFilter: wrapperspb.String("group-filter"),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:        []string{"ldaps://ldap1"},
							State:       "active-private",
							GroupDn:     wrapperspb.String("group-dn"),
							GroupAttr:   wrapperspb.String("group-attr"),
							GroupFilter: wrapperspb.String("group-filter"),
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "no-change",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.certificates"},
				},
				Item: &pb.AuthMethod{
					Name: &wrapperspb.StringValue{Value: "default"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "no changes were made to the existing AuthMethod",
		},
		{
			name: "valid-port-number",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.urls"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls: []string{"ldaps://ldap2:8156"},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Version:     2,
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        ldap.Subtype.String(),
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls:  []string{"ldaps://ldap2:8156"},
							State: "active-private",
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           ldapAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "invalid-port-number",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.urls"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							Urls: []string{"ldaps://ldap2:9999999"},
						},
					},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "port 9999999 in url ldaps://ldap2:9999999 is not valid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			am, cleanup := freshAuthMethod(t, tc.newAttrsOverride)
			defer cleanup()

			tc.req.Item.Version = am.GetVersion()

			if tc.req.GetId() == "" {
				tc.req.Id = am.GetId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = am.GetId()
				tc.res.Item.CreatedTime = am.GetCreatedTime()
			}
			got, gErr := tested.UpdateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			// TODO: When handlers move to domain errors remove wantErr and rely errors.Match here.
			if tc.err != nil || tc.wantErr {
				require.Error(gErr)
				if tc.err != nil {
					assert.True(errors.Is(gErr, tc.err), "UpdateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				}
				if tc.errContains != "" {
					assert.Contains(gErr.Error(), tc.errContains)
				}
				return
			}
			require.NoError(gErr)
			if tc.res == nil {
				require.Nil(got)
			}
			cmpOptions := []cmp.Option{
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			}
			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAuthMethod response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				created := am.GetCreatedTime().AsTime()

				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated auth_method should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Ignore all values which are hard to compare against.
				cmpOptions = append(
					cmpOptions,
					protocmp.IgnoreFields(&pb.AuthMethod{}, "updated_time"),
					protocmp.SortRepeatedFields(&pb.LdapAuthMethodAttributes{}, "account_attribute_maps", "urls", "certificates"),
					protocmp.IgnoreFields(&pb.LdapAuthMethodAttributes{}, "bind_password_hmac", "client_certificate_key_hmac"),
				)
				assert.NotEqual("bind_password", got.Item.GetLdapAuthMethodsAttributes().GetBindPasswordHmac())
				assert.NotEqual("client_certificate_key", got.Item.GetLdapAuthMethodsAttributes().GetClientCertificateKeyHmac())
			}
			assert.Empty(cmp.Diff(got, tc.res, cmpOptions...), "UpdateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestAuthenticate_Ldap(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testRootWrapper))
	opt := event.TestWithObservationSink(t)
	c := event.TestEventerConfig(t, "Test_StartAuth_to_Callback", opt)
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	c.EventerConfig.TelemetryEnabled = true
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-Test_Authenticate", event.WithEventerConfig(&c.EventerConfig)))
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, testConn, testRootWrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(testCtx, testRw, testRw, testKms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(testCtx, testRw, testRw, testKms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(testCtx, testRw, testRw, testKms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(testCtx, testRw, testRw, testKms)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(testCtx, testRw, testRw, testKms)
	}

	orgDbWrapper, err := testKms.GetWrapper(testCtx, o.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
		testdirectory.WithLogger(t, logger),
	)
	groups := []*gldap.Entry{
		testdirectory.NewGroup(t, "admin", []string{"alice"}),
		testdirectory.NewGroup(t, "users", []string{"alice"}),
	}
	users := testdirectory.NewUsers(t, []string{"alice"}, testdirectory.WithMembersOf(t, "admin", "users"))
	users2 := testdirectory.NewUsers(t, []string{"bob"})
	td.SetUsers(append(users, users2...)...)
	td.SetGroups(groups...)

	tdCerts, err := ldap.ParseCertificates(testCtx, td.Cert())
	require.NoError(t, err)

	testAm := ldap.TestAuthMethod(t, testConn, orgDbWrapper, o.PublicId,
		[]string{fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port())},
		ldap.WithCertificates(testCtx, tdCerts...),
		ldap.WithDiscoverDn(testCtx),
		ldap.WithEnableGroups(testCtx),
		ldap.WithUserDn(testCtx, testdirectory.DefaultUserDN),
		ldap.WithGroupDn(testCtx, testdirectory.DefaultGroupDN),
	)

	iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, testConn, testRootWrapper), o, testAm.PublicId)

	testManagedGrp := ldap.TestManagedGroup(t, testConn, testAm, []string{"cn=admin,ou=groups,dc=example,dc=org"})

	const (
		testLoginName  = "alice"
		testPassword   = "password"
		testLoginName2 = "bob"
	)

	testAcct := ldap.TestAccount(t, testConn, testAm, testLoginName)

	tests := []struct {
		name            string
		acctId          string
		request         *pbs.AuthenticateRequest
		actions         []string
		wantType        string
		wantGroups      []string
		wantErr         error
		wantErrContains string
	}{
		{
			name:   "basic-with-groups",
			acctId: testAcct.PublicId,
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantGroups: []string{testManagedGrp.PublicId},
			wantType:   "token",
		},
		{
			name: "basic-without-groups",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName2,
						Password:  testPassword,
					},
				},
			},
			wantType: "token",
		},
		{
			name:   "cookie-type",
			acctId: testAcct.PublicId,
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "cookie",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantType: "cookie",
		},
		{
			name:   "no-token-type",
			acctId: testAcct.PublicId,
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
		},
		{
			name: "bad-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "email",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no-authmethod",
			request: &pbs.AuthenticateRequest{
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "wrong-password",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName,
						Password:  "wrong",
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
		{
			name: "wrong-login-name",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: "wrong",
						Password:  testPassword,
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
		{
			name: "no-attributes",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "token",
				Attrs:        &pbs.AuthenticateRequest_LdapLoginAttributes{},
			},
			wantErr:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: `Details: {{name: "attributes", desc: "This is a required field."}}`,
		},
		{
			name:    "with-callback-action",
			acctId:  testAcct.PublicId,
			actions: []string{"callback"},
			request: &pbs.AuthenticateRequest{
				AuthMethodId: testAm.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantGroups:      []string{testManagedGrp.PublicId},
			wantErr:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: `Details: {{name: "request_path", desc: "callback is not a valid action for this auth method."}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := authmethods.NewService(testCtx, testKms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
			require.NoError(err)

			resp, err := s.Authenticate(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), auth.WithActions(tc.actions)), tc.request)
			if tc.wantErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tc.wantErr), "Got %#v, wanted %#v", err, tc.wantErr)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)

			aToken := resp.GetAuthTokenResponse()
			assert.NotEmpty(aToken.GetId())
			assert.NotEmpty(aToken.GetToken())
			assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
			assert.Equal(testAm.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetUpdatedTime())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetApproximateLastUsedTime())
			assert.Equal(testAm.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(tc.wantType, resp.GetType())
			sinkFileName := c.ObservationEvents.Name()
			defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(sinkFileName)
			require.NoError(err)
			gotRes := &cloudevents.Event{}
			err = json.Unmarshal(b, gotRes)
			require.NoErrorf(err, "json: %s", string(b))
			details, ok := gotRes.Data.(map[string]any)["details"]
			require.True(ok)
			for _, key := range details.([]any) {
				assert.Contains(key.(map[string]any)["payload"], "user_id")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_start")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_end")
			}
			// support testing for pre-provisioned accounts
			if tc.acctId != "" {
				assert.Equal(tc.acctId, aToken.GetAccountId())
			}

			names := ldap.TestGetAcctManagedGroups(t, testConn, aToken.GetAccountId())
			if len(tc.wantGroups) > 0 {
				assert.Equal(tc.wantGroups, names)
			}
		})
	}
}
