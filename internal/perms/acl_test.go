// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package perms

import (
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
	scope  string
	grants []string
}

func Test_ACLAllowed(t *testing.T) {
	t.Parallel()

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
			scope: "o_a",
			grants: []string{
				"id=ampw_bar;actions=read,update",
				"id=ampw_baz;actions=read:self,update",
				"type=host-catalog;actions=create",
				"type=target;actions=list",
				"id=*;type=host-set;actions=list,create",
			},
		},
		{
			scope: "o_b",
			grants: []string{
				"id=*;type=host-set;actions=list,create",
				"id=hcst_mypin;type=host;actions=*;output_fields=name,description",
				"id=*;type=*;actions=authenticate",
				"id=*;type=*;output_fields=id",
			},
		},
		{
			scope: "o_d",
			grants: []string{
				"id=*;type=*;actions=create,update",
				"id=*;type=session;actions=*",
				"id=*;type=account;actions=update;output_fields=id,version",
			},
		},
	}
	templateGrants := []scopeGrant{
		{
			scope: "o_c",
			grants: []string{
				"id={{user.id }};actions=read,update",
				"id={{ account.id}};actions=change-password",
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
			resource:    Resource{ScopeId: "o_a", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Create, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id no matching action",
			resource:    Resource{ScopeId: "o_a", Id: "a_foo", Type: resource.Role},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id and matching action",
			resource:    Resource{ScopeId: "o_a", Id: "ampw_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.Update, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and type and all action with valid pin",
			resource:    Resource{ScopeId: "o_b", Pin: "hcst_mypin", Type: resource.Host},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true, outputFields: []string{"description", "id", "name"}},
				{action: action.Update, authorized: true, outputFields: []string{"description", "id", "name"}},
				{action: action.Delete, authorized: true, outputFields: []string{"description", "id", "name"}},
			},
		},
		{
			name:        "matching scope and type and all action but bad pin",
			resource:    Resource{ScopeId: "o_b", Pin: "notmypin", Type: resource.Host},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, outputFields: []string{"id"}},
				{action: action.Update, outputFields: []string{"id"}},
				{action: action.Delete, outputFields: []string{"id"}},
			},
		},
		{
			name:        "matching scope and id and some action",
			resource:    Resource{ScopeId: "o_b", Id: "myhost", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true, outputFields: []string{"id"}},
				{action: action.Create, authorized: true, outputFields: []string{"id"}},
				{action: action.AddHosts, outputFields: []string{"id"}},
			},
		},
		{
			name:        "matching scope and id and all action but bad specifier",
			resource:    Resource{ScopeId: "o_b", Id: "id_g"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, outputFields: []string{"id"}},
				{action: action.Update, outputFields: []string{"id"}},
				{action: action.Delete, outputFields: []string{"id"}},
			},
		},
		{
			name:        "matching scope and not matching type",
			resource:    Resource{ScopeId: "o_a", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and matching type",
			resource:    Resource{ScopeId: "o_a", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true},
				{action: action.Create, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope, type, action, random id and bad pin",
			resource:    Resource{ScopeId: "o_a", Id: "anything", Type: resource.HostCatalog, Pin: "ampw_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Update},
				{action: action.Delete},
				{action: action.Read},
			},
		},
		{
			name:        "wrong scope and matching type",
			resource:    Resource{ScopeId: "o_bad", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List},
				{action: action.Create},
				{action: action.Delete},
			},
		},
		{
			name:        "any id",
			resource:    Resource{ScopeId: "o_b", Type: resource.AuthMethod},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, outputFields: []string{"id"}},
				{action: action.Authenticate, authorized: true, outputFields: []string{"id"}},
				{action: action.Delete, outputFields: []string{"id"}},
			},
		},
		{
			name:        "bad templated user id",
			resource:    Resource{ScopeId: "o_c"},
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
			resource:    Resource{ScopeId: "o_c", Id: "u_abcd1234"},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.Update, authorized: true},
			},
			userId: "u_abcd1234",
		},
		{
			name:        "bad templated old account id",
			resource:    Resource{ScopeId: "o_c"},
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
			resource:    Resource{ScopeId: "o_c", Id: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix)},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.ChangePassword, authorized: true},
				{action: action.Update},
			},
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
		},
		{
			name:        "bad templated new account id",
			resource:    Resource{ScopeId: "o_c"},
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
			resource:    Resource{ScopeId: "o_c", Id: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix)},
			scopeGrants: append(commonGrants, templateGrants...),
			actionsAuthorized: []actionAuthorized{
				{action: action.ChangePassword, authorized: true},
				{action: action.Update},
			},
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
		},
		{
			name:        "all type",
			resource:    Resource{ScopeId: "o_d", Type: resource.Account},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Create, authorized: true},
				{action: action.Update, authorized: true, outputFields: []string{"id", "version"}},
			},
			userId: "u_abcd1234",
		},
		{
			name:        "list with top level list",
			resource:    Resource{ScopeId: "o_a", Type: resource.Target},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true},
			},
		},
		{
			name:        "list sessions with wildcard actions",
			resource:    Resource{ScopeId: "o_d", Type: resource.Session},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List, authorized: true},
			},
		},
		{
			name:        "read self with top level read",
			resource:    Resource{ScopeId: "o_a", Id: "ampw_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.ReadSelf, authorized: true},
			},
		},
		{
			name:        "read self only",
			resource:    Resource{ScopeId: "o_a", Id: "ampw_baz"},
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
					scope: scope.Global.String(),
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
					scope: scope.Global.String(),
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
					grant, err := Parse(sg.scope, g, WithAccountId(test.accountId), WithUserId(test.userId))
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

func TestACL_ListPermissions(t *testing.T) {
	tests := []struct {
		name           string
		userId         string
		aclGrants      []scopeGrant
		scopes         map[string]*scopes.ScopeInfo // *scopes.ScopeInfo isn't used at the moment.
		resourceType   resource.Type
		actionSet      action.ActionSet
		expPermissions []Permission
	}{
		{
			name: "scope_not_present_in_scope_map",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=session;actions=list,read"},
				},
			},
			scopes: map[string]*scopes.ScopeInfo{
				"o_non_existent_scope": nil,
				"o_this_one_too":       nil,
			},
			resourceType:   resource.Session,
			actionSet:      action.ActionSet{action.Read},
			expPermissions: []Permission{},
		},
		{
			name: "requested_resource_mismatch",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=target;actions=list,read"}, // List & Read for all Targets
				},
			},
			scopes:         map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType:   resource.Session, // We're requesting sessions.
			actionSet:      action.ActionSet{action.Read},
			expPermissions: []Permission{},
		},
		{
			name: "requested_actions_not_available_for_requested_scope_id",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=session;actions=delete"},
				},
			},
			scopes:         map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType:   resource.Session,
			actionSet:      action.ActionSet{action.Read},
			expPermissions: []Permission{},
		},
		{
			name: "no_specific_id_or_wildcard_provided",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"type=*;actions=list,read"},
				},
			},
			scopes:         map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType:   resource.Session,
			actionSet:      action.ActionSet{action.Read},
			expPermissions: []Permission{},
		},
		{
			name: "allow_all_ids",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=session;actions=list,read"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
			},
		},
		{
			name: "allow_all_ids_read:self_action",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=session;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.ReadSelf},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    true,
					All:         true,
				},
			},
		},
		{
			name: "allow_specific_ids",
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"id=s_1;type=session;actions=list,read",
						"id=s_2;type=session;actions=list,read",
						"id=s_3;type=session;actions=list,read",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: []string{"s_1", "s_2", "s_3"},
					OnlySelf:    false,
					All:         false,
				},
			},
		},
		{
			name: "no_specific_type_1",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=*;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.ReadSelf},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    true,
					All:         true,
				},
			},
		},
		{
			name: "list_and_noop_action_with_wildcard_id",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=session;actions=list,no-op"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.List},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
			},
		},
		{
			name: "list_and_noop_action_with_wildcard_id_only_read_action_available",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=session;actions=list,no-op"},
				},
			},
			scopes:         map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType:   resource.Session,
			actionSet:      action.ActionSet{action.Read},
			expPermissions: []Permission{},
		},
		{
			name: "list_and_noop_action_with_pinned_ids",
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"id=s_1;type=session;actions=list,no-op",
						"id=s_2;type=session;actions=list,no-op",
						"id=s_3;type=session;actions=list,no-op",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.List},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: []string{"s_1", "s_2", "s_3"},
					OnlySelf:    false,
					All:         false,
				},
			},
		},
		{
			name: "no_specific_type_2",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=*;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Host,
			actionSet:    action.ActionSet{action.ReadSelf},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Host,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    true,
					All:         true,
				},
			},
		},
		{
			name: "grant_hierarchy_is_respected",
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"id=*;type=*;actions=*",
						"id=*;type=session;actions=cancel:self,list,read:self",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.NoOp, action.Read, action.ReadSelf, action.Cancel, action.CancelSelf},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
			},
		},
		{
			name: "full_access_1",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=*;actions=*"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read, action.Create, action.Delete},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
			},
		},
		{
			name: "full_access_2",
			aclGrants: []scopeGrant{
				{
					scope:  "o_1",
					grants: []string{"id=*;type=*;actions=*"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Host,
			actionSet:    action.ActionSet{action.Read, action.Create, action.Delete},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Host,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
			},
		},
		{
			name: "multiple_scopes",
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"id=s_1;type=session;actions=list,read",
						"id=s_2;type=session;actions=list,read",
						"id=s_3;type=session;actions=list,read",
					},
				},
				{
					scope:  "o_2",
					grants: []string{"id=*;type=session;actions=list,read:self"},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil, "o_2": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read, action.ReadSelf},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: []string{"s_1", "s_2", "s_3"},
					OnlySelf:    false,
					All:         false,
				},
				{
					ScopeId:     "o_2",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    true,
					All:         true,
				},
			},
		},
		{
			name:         "recovery_user_has_full_access_sessions",
			userId:       globals.RecoveryUserId,
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil, "o_2": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read, action.Create, action.Delete},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
				{
					ScopeId:     "o_2",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
			},
		},
		{
			name:         "recovery_user_has_full_access_targets",
			userId:       globals.RecoveryUserId,
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil, "o_2": nil},
			resourceType: resource.Target,
			actionSet:    action.ActionSet{action.Read, action.Create, action.Delete},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Target,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
				{
					ScopeId:     "o_2",
					Resource:    resource.Target,
					Action:      action.List,
					ResourceIds: nil,
					OnlySelf:    false,
					All:         true,
				},
			},
		},
		{
			name: "list_type_id_read_grants",
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"type=session;actions=list",
						"id=s_2;type=session;actions=read",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: []string{"s_2"},
					OnlySelf:    false,
					All:         false,
				},
			},
		},
		{
			name: "list_type_with_ids_and_wildcard_id_read_grant",
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						// This isn't a valid grant because it pins ids and
						// operates on a collection action.
						"id=s_1;type=session;actions=list",

						// But this grant allows read on any session, therefore
						// it also allows list on any session.
						"id=*;type=session;actions=read",
					},
				},
			},
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read},
			expPermissions: []Permission{
				{
					ScopeId:  "o_1",
					Resource: resource.Session,
					Action:   action.List,
					OnlySelf: false,
					All:      true,
				},
			},
		},
		{
			name:         "read:self_override",
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read, action.ReadSelf},
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"type=session;actions=list,read:self",
						"id=s_1;type=session;actions=read",
					},
				},
			},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: []string{"s_1"},
					All:         false,
					OnlySelf:    false,
				},
			},
		},
		{
			name:         "other_actions_enable_listing_if_part_of_action_set_1",
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read, action.Cancel},
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"type=session;actions=list",
						"id=s_1;type=session;actions=read",
						"id=*;type=session;actions=cancel",
					},
				},
			},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: []string{"s_1"},
					All:         true,
					OnlySelf:    false,
				},
			},
		},
		{
			name:         "other_actions_enable_listing_if_part_of_action_set_2",
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read, action.Create},
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"type=session;actions=list",
						"id=s_1;type=session;actions=read",
						"id=*;type=session;actions=cancel",
					},
				},
			},
			expPermissions: []Permission{
				{
					ScopeId:     "o_1",
					Resource:    resource.Session,
					Action:      action.List,
					ResourceIds: []string{"s_1"},
					// Note the grant that otherwise would enable listing all
					// has "cancel" action which in this test isn't part of the
					// action set.
					All:      false,
					OnlySelf: false,
				},
			},
		},
		{
			name:         "mismatched_resource_grants",
			scopes:       map[string]*scopes.ScopeInfo{"o_1": nil},
			resourceType: resource.Session,
			actionSet:    action.ActionSet{action.Read, action.Cancel},
			aclGrants: []scopeGrant{
				{
					scope: "o_1",
					grants: []string{
						"type=target;actions=list",
						"id=s_1;type=session;actions=read",
					},
				},
			},
			expPermissions: []Permission{},
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
				for _, g := range sg.grants {
					grant, err := Parse(sg.scope, g, WithSkipFinalValidation(true))
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

	type input struct {
		name              string
		grant             string
		templatedType     bool
		shouldHaveSuccess bool
	}
	tests := []input{
		{
			name:  "id-specific",
			grant: "id=foobar;actions=%s",
		},
		{
			name:              "wildcard-id",
			grant:             "id=*;type=%s;actions=%s",
			templatedType:     true,
			shouldHaveSuccess: true,
		},
		{
			name:  "wildcard-id-and-type",
			grant: "id=*;type=*;actions=%s",
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
			for i := resource.Type(1); i <= resource.Credential; i++ {
				if i == resource.Controller || i == resource.Worker {
					continue
				}
				for j := action.Type(1); j <= action.ReadCertificateAuthority; j++ {
					res := Resource{
						ScopeId: scope.Global.String(),
						Id:      "foobar",
						Type:    resource.Type(i),
					}
					grant := test.grant
					if test.templatedType {
						grant = fmt.Sprintf(grant, resource.Type(i).String(), action.Type(j).String())
					} else {
						grant = fmt.Sprintf(grant, action.Type(j).String())
					}

					parsedGrant, err := Parse(scope.Global.String(), grant, WithSkipFinalValidation(true))
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
