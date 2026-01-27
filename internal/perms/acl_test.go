// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scopeGrant struct {
	roleScope         string
	roleParentScopeId string
	grantScope        string
	grants            []string
}

func Test_ACLAllowed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type actionAuthorized struct {
		action       action.Type
		authorized   bool
		outputFields []string
	}
	type input struct {
		name              string
		scopeGrants       []scopeGrant
		resource          Resource
		actionsAuthorized []actionAuthorized
		userId            string
		accountId         string
	}

	// A set of common grants to use in the following tests
	commonGrants := []scopeGrant{
		{
			roleScope:  "o_a",
			grantScope: "o_a",
			grants: []string{
				"ids=ampw_bar,ampw_baz;actions=read,update",
				"ids=ampw_bop;actions=read:self,update",
				"type=host-catalog;actions=create",
				"type=target;actions=list",
				"ids=*;type=host-set;actions=list,create",
			},
		},
		{
			roleScope:  "o_b",
			grantScope: "o_b",
			grants: []string{
				"ids=*;type=host-set;actions=list,create",
				"ids=hcst_mypin;type=host;actions=*;output_fields=name,description",
				"ids=*;type=*;actions=authenticate",
				"ids=*;type=*;output_fields=id",
			},
		},
		{
			roleScope:  "o_d",
			grantScope: "o_d",
			grants: []string{
				"ids=*;type=*;actions=create,update",
				"ids=*;type=session;actions=*",
				"ids=*;type=account;actions=update;output_fields=id,version",
			},
		},
	}
	templateGrants := []scopeGrant{
		{
			roleScope:  "o_c",
			grantScope: "o_c",
			grants: []string{
				"ids={{user.id }};actions=read,update",
				"ids={{ account.id}};actions=change-password",
			},
		},
	}

	// See acl.go for expected allowed formats. The goal here is to basically
	// test those, but also test a whole bunch of nonconforming values.
	tests := []input{
		{
			name:     "no grants",
			resource: Resource{ScopeId: "foo", Id: "bar", Type: resource.HostCatalog},
			actionsAuthorized: []actionAuthorized{
				{action: action.Create},
				{action: action.Read},
			},
		},
		{
			name:        "no overlap",
			resource:    Resource{ScopeId: "foo", Id: "bar", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Create},
				{action: action.Read},
			},
		},
		{
			name:        "top level create with type only",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Create, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id no matching action",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "a_foo", Type: resource.Role},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id and matching action first id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "ampw_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.Update, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id and matching action second id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "ampw_baz"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.Update, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and type and all action with valid pin",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_b", Pin: "hcst_mypin", Type: resource.Host},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true, outputFields: []string{"description", "id", "name"}},
				{action: action.Update, authorized: true, outputFields: []string{"description", "id", "name"}},
				{action: action.Delete, authorized: true, outputFields: []string{"description", "id", "name"}},
			},
		},
		{
			name:        "matching scope and type and all action but bad pin",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_b", Pin: "notmypin", Type: resource.Host},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, outputFields: []string{"id"}},
				{action: action.Update, outputFields: []string{"id"}},
				{action: action.Delete, outputFields: []string{"id"}},
			},
		},
		{
			name:        "matching scope and id and some action",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_b", Id: "myhost", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true, outputFields: []string{"id"}},
				{action: action.Create, authorized: true, outputFields: []string{"id"}},
				{action: action.AddHosts, outputFields: []string{"id"}},
			},
		},
		{
			name:        "matching scope and id and all action but bad specifier",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_b", Id: "id_g"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, outputFields: []string{"id"}},
				{action: action.Update, outputFields: []string{"id"}},
				{action: action.Delete, outputFields: []string{"id"}},
			},
		},
		{
			name:        "matching scope and not matching type",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and matching type",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true},
				{action: action.Create, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope, type, action, random id and bad pin first id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "anything", Type: resource.HostCatalog, Pin: "ampw_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Update},
				{action: action.Delete},
				{action: action.Read},
			},
		},
		{
			name:        "matching scope, type, action, random id and bad pin second id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "anything", Type: resource.HostCatalog, Pin: "ampw_baz"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Update},
				{action: action.Delete},
				{action: action.Read},
			},
		},
		{
			name:        "wrong scope and matching type",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_bad", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List},
				{action: action.Create},
				{action: action.Delete},
			},
		},
		{
			name:        "any id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_b", Type: resource.AuthMethod},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, outputFields: []string{"id"}},
				{action: action.Authenticate, authorized: true, outputFields: []string{"id"}},
				{action: action.Delete, outputFields: []string{"id"}},
			},
		},
		{
			name:        "bad templated user id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_c"},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.List},
				{action: action.Authenticate},
				{action: action.Delete},
			},
			userId: "u_abcd1234",
		},
		{
			name:        "good templated user id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_c", Id: "u_abcd1234"},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.Update, authorized: true},
			},
			userId: "u_abcd1234",
		},
		{
			name:        "bad templated old account id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_c"},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.List},
				{action: action.Authenticate},
				{action: action.Delete},
			},
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
		},
		{
			name:        "good templated old account id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_c", Id: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix)},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.ChangePassword, authorized: true},
				{action: action.Update},
			},
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
		},
		{
			name:        "bad templated new account id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_c"},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.List},
				{action: action.Authenticate},
				{action: action.Delete},
			},
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
		},
		{
			name:        "good templated new account id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_c", Id: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix)},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.ChangePassword, authorized: true},
				{action: action.Update},
			},
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
		},
		{
			name:        "all type",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_d", Type: resource.Account},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Create, authorized: true},
				{action: action.Update, authorized: true, outputFields: []string{"id", "version"}},
			},
			userId: "u_abcd1234",
		},
		{
			name:        "list with top level list",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Type: resource.Target},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true},
			},
		},
		{
			name:        "list sessions with wildcard actions",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_d", Type: resource.Session},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true},
			},
		},
		{
			name:        "read self with top level read first id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "ampw_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.ReadSelf, authorized: true},
			},
		},
		{
			name:        "read self with top level read second id",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "ampw_baz"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.ReadSelf, authorized: true},
			},
		},
		{
			name:        "read self only",
			resource:    Resource{ParentScopeId: scope.Global.String(), ScopeId: "o_a", Id: "ampw_bop"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read},
				{action: action.ReadSelf, authorized: true},
			},
		},
		{
			name:     "create worker with create",
			resource: Resource{ScopeId: scope.Global.String(), Type: resource.Worker},
			scopeGrants: []scopeGrant{
				{
					roleScope:  scope.Global.String(),
					grantScope: scope.Global.String(),
					grants: []string{
						"type=worker;actions=create",
					},
				},
			},
			actionsAuthorized: []actionAuthorized{
				{action: action.CreateWorkerLed, authorized: true},
			},
		},
		{
			name:     "create worker with request only",
			resource: Resource{ScopeId: scope.Global.String(), Type: resource.Worker},
			scopeGrants: []scopeGrant{
				{
					roleScope:  scope.Global.String(),
					grantScope: scope.Global.String(),
					grants: []string{
						"type=worker;actions=create:worker-led",
					},
				},
			},
			actionsAuthorized: []actionAuthorized{
				{action: action.CreateWorkerLed, authorized: true},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var grants []Grant
			for _, sg := range test.scopeGrants {
				for _, g := range sg.grants {
					grant, err := Parse(ctx, GrantTuple{RoleScopeId: sg.roleScope, GrantScopeId: sg.grantScope, Grant: g}, WithAccountId(test.accountId), WithUserId(test.userId))
					require.NoError(t, err)
					grants = append(grants, grant)
				}
			}
			acl := NewACL(grants...)
			for _, aa := range test.actionsAuthorized {
				userId := test.userId
				if userId == "" {
					userId = "u_1234567890"
				}
				result := acl.Allowed(test.resource, aa.action, userId)
				assert.True(t, result.Authorized == aa.authorized, "action: %s, acl authorized: %t, test action authorized: %t", aa.action, result.Authorized, aa.authorized)
				fields, _ := result.OutputFields.Fields()
				assert.ElementsMatch(t, fields, aa.outputFields)
			}
		})
	}
}

func TestACL_ListResolvableAliasesPermissions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name                        string
		aclGrants                   []scopeGrant
		resourceType                resource.Type
		actionSet                   action.ActionSet
		expPermissions              []Permission
		skipGrantValidationChecking bool
	}{
		{
			name: "Requested resource mismatch",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=target;actions=list,read"}, // List & Read for all Targets
				},
			},
			resourceType:   resource.Session, // We're requesting sessions.
			actionSet:      action.NewActionSet(action.Read),
			expPermissions: []Permission{},
		},
		{
			name: "Requested actions not available for the requested scope id",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=session;actions=delete"},
				},
			},
			resourceType:   resource.Session,
			actionSet:      action.NewActionSet(action.Read),
			expPermissions: []Permission{},
		},
		{
			name: "No specific id or wildcard provided for `id` field",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"type=*;actions=list,read"},
				},
			},
			resourceType:                resource.Session,
			actionSet:                   action.NewActionSet(action.Read),
			expPermissions:              []Permission{},
			skipGrantValidationChecking: true,
		},
		{
			name: "Allow all ids",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=session;actions=update,read"},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Allow all ids, :self actions",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=session;actions=list,read:self"},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name: "Allow specific IDs",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants: []string{
						"ids=s_1;type=session;actions=list,read",
						"ids=s_2,s_3;type=session;actions=list,read",
					},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"s_1", "s_2", "s_3"},
					OnlySelf:          false,
					All:               false,
				},
			},
		},
		{
			name: "No specific type 1",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=*;actions=list,read:self"},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name: "List + No-op action with id wildcard",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=session;actions=list,no-op"},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.NoOp),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "List + No-op action with id wildcard, read present",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=session;actions=list,no-op"},
				},
			},
			resourceType:   resource.Session,
			actionSet:      action.NewActionSet(action.Read),
			expPermissions: []Permission{},
		},
		{
			name: "List + No-op action with specific ids",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants: []string{
						"ids=s_1;type=session;actions=list,no-op",
						"ids=s_2,s_3;type=session;actions=list,no-op",
					},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.NoOp),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"s_1", "s_2", "s_3"},
					OnlySelf:          false,
					All:               false,
				},
			},
		},
		{
			name: "No specific type 2",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=*;actions=list,read:self"},
				},
			},
			resourceType: resource.Host,
			actionSet:    action.NewActionSet(action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Host,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name: "Grant hierarchy is respected",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants: []string{
						"ids=*;type=*;actions=*",
						"ids=*;type=session;actions=cancel:self,list,read:self",
					},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.NoOp, action.Read, action.ReadSelf, action.Cancel, action.CancelSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Full access 1",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=*;actions=*"},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read, action.Create, action.Delete),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Full access 2",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants:            []string{"ids=*;type=*;actions=*"},
				},
			},
			resourceType: resource.Host,
			actionSet:    action.NewActionSet(action.Read, action.Create, action.Delete),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Host,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Multiple scopes",
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants: []string{
						"ids=s_1;type=session;actions=create,read",
						"ids=s_2,s_3;type=session;actions=update,read",
					},
				},
				{
					roleScope:         "o_2",
					grantScope:        "o_2",
					roleParentScopeId: scope.Global.String(),
					grants:            []string{"ids=*;type=session;actions=read:self"},
				},
			},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read, action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"s_1", "s_2", "s_3"},
					OnlySelf:          false,
					All:               false,
				},
				{
					RoleScopeId:       "o_2",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_2",
					Resource:          resource.Session,
					Action:            action.ListResolvableAliases,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name:         "separate_type_id_resource_grants",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:         "p_1",
					roleParentScopeId: "o_1",
					grantScope:        "p_1",
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "p_1",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "global_no_this_with_descendants",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeDescendants,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "global_with_this_with_descendants",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeDescendants,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "global",
					grantScope: "global",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: scope.Global.String(),
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "global_with_this_no_descendants",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: "global",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: scope.Global.String(),
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "global_no_this_with_valid_children",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeChildren,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeChildren,
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "global_with_this_with_valid_children_and_direct_grant",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: "global",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeChildren,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "global",
					grantScope: "p_1",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: scope.Global.String(),
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeChildren,
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: "p_1",
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "global_with_this_with_and_direct_grant",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: "global",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "global",
					grantScope: "p_1",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: scope.Global.String(),
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: "p_1",
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "global_with_this_with_multiple_direct_grants",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: "global",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "global",
					grantScope: "o_1",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "global",
					grantScope: "p_1",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: scope.Global.String(),
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: "o_1",
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: "p_1",
					Resource:     resource.Target,
					Action:       action.ListResolvableAliases,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "org_no_this_with_children_and_direct_grant",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        globals.GrantScopeChildren,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "o_2",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_2",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "o_2",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_2",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "org_with_this_with_children_and_direct_grant",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        globals.GrantScopeChildren,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "org_with_this_with_child_scope_direct_grants",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        globals.GrantScopeChildren,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "p_1a",
					roleParentScopeId: "o_1",
					grantScope:        "p_1a",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "p_1b",
					roleParentScopeId: "o_1",
					grantScope:        "p_1b",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "p_2",
					roleParentScopeId: "o_2",
					grantScope:        "p_2",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "p_1a",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1a",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "p_1b",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1b",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "p_2",
					RoleParentScopeId: "o_2",
					GrantScopeId:      "p_2",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "org_with_this_with_child_scope_direct_grants_parent_has_resource_all",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        globals.GrantScopeChildren,
					grants: []string{
						"ids=*;type=target;actions=read",
					},
				},
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        "o_1",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "p_1a",
					roleParentScopeId: "o_1",
					grantScope:        "p_1a",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "p_1b",
					roleParentScopeId: "o_1",
					grantScope:        "p_1b",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:         "p_2",
					roleParentScopeId: "o_2",
					grantScope:        "p_2",
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					All:               true,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "p_2",
					RoleParentScopeId: "o_2",
					GrantScopeId:      "p_2",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "org_with_child_scope_and_proj_granting_different_id",
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:         "o_1",
					roleParentScopeId: scope.Global.String(),
					grantScope:        globals.GrantScopeChildren,
					grants: []string{
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					// project role that's a child of o_1
					// granting a different resource than o_1 role
					roleScope:         "p_1",
					roleParentScopeId: "o_1",
					grantScope:        "p_1",
					grants: []string{
						"ids=ttcp_abcdefghij;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "p_1",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1",
					Resource:          resource.Target,
					Action:            action.ListResolvableAliases,
					ResourceIds:       []string{"ttcp_abcdefghij"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var grants []Grant
			for _, sg := range tt.aclGrants {
				if sg.roleScope == "" {
					sg.roleScope = sg.grantScope
				}
				for _, g := range sg.grants {
					grant, err := Parse(ctx, GrantTuple{RoleScopeId: sg.roleScope, RoleParentScopeId: sg.roleParentScopeId, GrantScopeId: sg.grantScope, Grant: g}, WithSkipFinalValidation(tt.skipGrantValidationChecking))
					require.NoError(t, err)
					grants = append(grants, grant)
				}
			}

			acl := NewACL(grants...)
			perms := acl.ListResolvableAliasesPermissions(tt.resourceType, tt.actionSet)
			assert.ElementsMatch(t, tt.expPermissions, perms)
		})
	}
}

func TestACL_ListPermissions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name                        string
		userId                      string
		aclGrants                   []scopeGrant
		scopes                      map[string]*scopes.ScopeInfo // *scopes.ScopeInfo isn't used at the moment.
		resourceType                resource.Type
		actionSet                   action.ActionSet
		expPermissions              []Permission
		skipGrantValidationChecking bool
	}{
		{
			name: "Requested scope(s) not present in ACL scope map",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=session;actions=list,read"},
				},
			},
			scopes: map[string]*scopes.ScopeInfo{
				"o_non_existent_scope": nil,
				"o_this_one_too":       nil,
			},
			resourceType:   resource.Session,
			actionSet:      action.NewActionSet(action.Read),
			expPermissions: []Permission{},
		},
		{
			name: "Requested resource mismatch",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=target;actions=list,read"}, // List & Read for all Targets
				},
			},
			scopes:         map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType:   resource.Session, // We're requesting sessions.
			actionSet:      action.NewActionSet(action.Read),
			expPermissions: []Permission{},
		},
		{
			name: "Requested actions not available for the requested scope id",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=session;actions=delete"},
				},
			},
			scopes:         map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType:   resource.Session,
			actionSet:      action.NewActionSet(action.Read),
			expPermissions: []Permission{},
		},
		{
			name: "No specific id or wildcard provided for `id` field",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"type=*;actions=list,read"},
				},
			},
			scopes:                      map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType:                resource.Session,
			actionSet:                   action.NewActionSet(action.Read),
			expPermissions:              []Permission{},
			skipGrantValidationChecking: true,
		},
		{
			name: "Allow all ids",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=session;actions=list,read"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Allow all ids, :self actions",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=session;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name: "Allow specific IDs",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants: []string{
						"ids=s_1;type=session;actions=list,read",
						"ids=s_2,s_3;type=session;actions=list,read",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       []string{"s_1", "s_2", "s_3"},
					OnlySelf:          false,
					All:               false,
				},
			},
		},
		{
			name: "No specific type 1",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=*;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name: "List + No-op action with id wildcard",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=session;actions=list,no-op"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.NoOp),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "List + No-op action with id wildcard, read present",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=session;actions=list,no-op"},
				},
			},
			scopes:         map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType:   resource.Session,
			actionSet:      action.NewActionSet(action.Read),
			expPermissions: []Permission{},
		},
		{
			name: "List + No-op action with specific ids",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants: []string{
						"ids=s_1;type=session;actions=list,no-op",
						"ids=s_2,s_3;type=session;actions=list,no-op",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.NoOp),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       []string{"s_1", "s_2", "s_3"},
					OnlySelf:          false,
					All:               false,
				},
			},
		},
		{
			name: "No specific type 2",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=*;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Host,
			actionSet:    action.NewActionSet(action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Host,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name: "Grant hierarchy is respected",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants: []string{
						"ids=*;type=*;actions=*",
						"ids=*;type=session;actions=cancel:self,list,read:self",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.NoOp, action.Read, action.ReadSelf, action.Cancel, action.CancelSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Full access 1",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=*;actions=*"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read, action.Create, action.Delete),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Full access 2",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants:     []string{"ids=*;type=*;actions=*"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Host,
			actionSet:    action.NewActionSet(action.Read, action.Create, action.Delete),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Host,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name: "Multiple scopes",
			aclGrants: []scopeGrant{
				{
					grantScope: "o_1",
					grants: []string{
						"ids=s_1;type=session;actions=list,read",
						"ids=s_2,s_3;type=session;actions=list,read",
					},
				},
				{
					grantScope: "o_2",
					grants:     []string{"ids=*;type=session;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}, "o_2": {Id: "o_2", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read, action.ReadSelf),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       []string{"s_1", "s_2", "s_3"},
					OnlySelf:          false,
					All:               false,
				},
				{
					RoleScopeId:       "o_2",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_2",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          true,
					All:               true,
				},
			},
		},
		{
			name:         "Allow recovery user full access to sessions",
			userId:       globals.RecoveryUserId,
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}, "o_2": {Id: "o_2", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Session,
			actionSet:    action.NewActionSet(action.Read, action.Create, action.Delete),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
				{
					RoleScopeId:       "o_2",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_2",
					Resource:          resource.Session,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name:         "Allow recovery user full access to targets",
			userId:       globals.RecoveryUserId,
			scopes:       map[string]*scopes.ScopeInfo{"o_1": {Id: "o_1", ParentScopeId: scope.Global.String()}, "o_2": {Id: "o_2", ParentScopeId: scope.Global.String()}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Create, action.Delete),
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_1",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
				{
					RoleScopeId:       "o_2",
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      "o_2",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       nil,
					OnlySelf:          false,
					All:               true,
				},
			},
		},
		{
			name:         "separate_type_id_resource_grants",
			scopes:       map[string]*scopes.ScopeInfo{"p_1": {Id: "p_1", ParentScopeId: "o_1"}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					grantScope: "p_1",
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "p_1",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "global_no_this_with_descendants",
			scopes:       map[string]*scopes.ScopeInfo{"p_1": {Id: "p_1", ParentScopeId: "o_1"}, "global": {Id: "global", ParentScopeId: ""}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeDescendants,
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "p_1",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "global_with_this_with_descendants",
			scopes:       map[string]*scopes.ScopeInfo{"p_1": {Id: "p_1", ParentScopeId: "o_1"}, "global": {Id: "global", ParentScopeId: ""}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeDescendants,
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "global",
					grantScope: "global",
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "p_1",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:  "global",
					GrantScopeId: "global",
					Resource:     resource.Target,
					Action:       action.List,
					ResourceIds:  []string{"ttcp_1234567890"},
					All:          false,
					OnlySelf:     false,
				},
			},
		},
		{
			name:         "global_no_this_with_invalid_children",
			scopes:       map[string]*scopes.ScopeInfo{"p_1": {Id: "p_1", ParentScopeId: "o_1"}, "global": {Id: "global", ParentScopeId: ""}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeChildren,
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: nil,
		},
		{
			name:         "global_no_this_with_valid_children",
			scopes:       map[string]*scopes.ScopeInfo{"p_1": {Id: "p_1", ParentScopeId: "o_1"}, "o_2": {Id: "o_2", ParentScopeId: "global"}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "global",
					grantScope: globals.GrantScopeChildren,
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_2",
					RoleParentScopeId: "global",
					GrantScopeId:      "o_2",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "org_no_this_with_children_and_direct_grant",
			scopes:       map[string]*scopes.ScopeInfo{"p_1": {Id: "p_1", ParentScopeId: "o_1"}, "o_2": {Id: "o_2", ParentScopeId: "global"}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "o_1",
					grantScope: globals.GrantScopeChildren,
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "o_2",
					grantScope: "o_2",
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "p_1",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "o_2",
					RoleParentScopeId: "global",
					GrantScopeId:      "o_2",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
		{
			name:         "org_with_this_with_children_and_direct_grant",
			scopes:       map[string]*scopes.ScopeInfo{"p_1": {Id: "p_1", ParentScopeId: "o_1"}, "o_2": {Id: "o_2", ParentScopeId: "global"}, "o_1": {Id: "o_1", ParentScopeId: "global"}},
			resourceType: resource.Target,
			actionSet:    action.NewActionSet(action.Read, action.Cancel),
			aclGrants: []scopeGrant{
				{
					roleScope:  "o_1",
					grantScope: globals.GrantScopeChildren,
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
				{
					roleScope:  "o_1",
					grantScope: "o_1",
					grants: []string{
						"type=target;actions=list",
						"ids=ttcp_1234567890;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					RoleScopeId:       "o_1",
					RoleParentScopeId: "global",
					GrantScopeId:      "o_1",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
				{
					RoleScopeId:       "p_1",
					RoleParentScopeId: "o_1",
					GrantScopeId:      "p_1",
					Resource:          resource.Target,
					Action:            action.List,
					ResourceIds:       []string{"ttcp_1234567890"},
					All:               false,
					OnlySelf:          false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userId := tt.userId
			if userId == "" {
				userId = "u_1234567890"
			}
			var grants []Grant
			for _, sg := range tt.aclGrants {
				if sg.roleScope == "" {
					sg.roleScope = sg.grantScope
				}
				for _, g := range sg.grants {
					grant, err := Parse(ctx, GrantTuple{RoleScopeId: sg.roleScope, GrantScopeId: sg.grantScope, Grant: g}, WithSkipFinalValidation(tt.skipGrantValidationChecking))
					require.NoError(t, err)
					grants = append(grants, grant)
				}
			}

			acl := NewACL(grants...)
			perms := acl.ListPermissions(tt.scopes, tt.resourceType, tt.actionSet, userId)
			require.ElementsMatch(t, tt.expPermissions, perms)
		})
	}
}

func TestJsonMarshal(t *testing.T) {
	res := &Resource{
		ScopeId: "scope",
		Id:      "id",
		Type:    resource.Controller,
		Pin:     "",
	}

	out, err := json.Marshal(res)
	require.NoError(t, err)
	assert.Equal(t, `{"scope_id":"scope","id":"id","type":"controller"}`, string(out))
}

// Test_AnonRestrictions loops through every resource and action and ensures
// that it always fails for the anonymous user, regardless of what is granted,
// except for the specific things allowed.
func Test_AnonRestrictions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type input struct {
		name              string
		grant             string
		templatedType     bool
		shouldHaveSuccess bool
	}
	tests := []input{
		{
			name:  "id-specific",
			grant: "ids=foobar;actions=%s",
		},
		{
			name:  "ids-specific",
			grant: "ids=foobar;actions=%s",
		},
		{
			name:              "wildcard-id",
			grant:             "ids=*;type=%s;actions=%s",
			templatedType:     true,
			shouldHaveSuccess: true,
		},
		{
			name:              "wildcard-ids",
			grant:             "ids=*;type=%s;actions=%s",
			templatedType:     true,
			shouldHaveSuccess: true,
		},
		{
			name:  "wildcard-id-and-type",
			grant: "ids=*;type=*;actions=%s",
		},
		{
			name:  "wildcard-ids-and-type",
			grant: "ids=*;type=*;actions=%s",
		},
		{
			name:              "no-id",
			grant:             "type=%s;actions=%s",
			templatedType:     true,
			shouldHaveSuccess: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			for i := resource.Type(1); i <= resource.AppToken; i++ {
				if i == resource.Controller || i == resource.Worker {
					continue
				}
				for j := action.Type(1); j <= action.RevokeSelf; j++ {
					id := "foobar"
					prefixes := globals.ResourcePrefixesFromType(resource.Type(i))
					if len(prefixes) > 0 {
						id = fmt.Sprintf("%s_%s", prefixes[0], id)
						// If it's global scope, correct it
						if id == "global_foobar" {
							id = "global"
						}
					}
					res := Resource{
						ScopeId: scope.Global.String(),
						Id:      id,
						Type:    resource.Type(i),
					}
					grant := test.grant
					if test.templatedType {
						grant = fmt.Sprintf(grant, resource.Type(i).String(), action.Type(j).String())
					} else {
						grant = fmt.Sprintf(grant, action.Type(j).String())
					}

					parsedGrant, err := Parse(ctx, GrantTuple{RoleScopeId: scope.Global.String(), GrantScopeId: scope.Global.String(), Grant: grant}, WithSkipFinalValidation(true))
					require.NoError(err)

					acl := NewACL(parsedGrant)
					results := acl.Allowed(res, action.Type(j), globals.AnonymousUserId)

					switch test.shouldHaveSuccess {
					case true:
						// Ensure it's one of the specific cases and fail otherwise
						switch {
						case i == resource.Scope && (j == action.List || j == action.NoOp):
							assert.True(results.Authorized, fmt.Sprintf("i: %v, j: %v", i, j))
						case i == resource.AuthMethod && (j == action.List || j == action.NoOp || j == action.Authenticate):
							assert.True(results.Authorized, fmt.Sprintf("i: %v, j: %v", i, j))
						default:
							assert.False(results.Authorized, fmt.Sprintf("i: %v, j: %v", i, j))
						}
					default:
						// Should always fail
						assert.False(results.Authorized)
					}
				}
			}
		})
	}
}
