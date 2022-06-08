package perms

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ACLAllowed(t *testing.T) {
	t.Parallel()

	type scopeGrant struct {
		scope  string
		grants []string
	}
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
				"id=a_bar;actions=read,update",
				"id=a_baz;actions=read:self,update",
				"type=host-catalog;actions=create",
				"type=target;actions=list",
				"id=*;type=host-set;actions=list,create",
			},
		},
		{
			scope: "o_b",
			grants: []string{
				"id=*;type=host-set;actions=list,create",
				"id=mypin;type=host;actions=*;output_fields=name,description",
				"id=*;type=*;actions=authenticate",
				"id=*;type=*;output_fields=id",
			},
		},
		{
			scope: "o_c",
			grants: []string{
				"id={{user.id }};actions=read,update",
				"id={{ account.id}};actions=change-password",
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
			resource:    Resource{ScopeId: "o_a", Id: "a_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.Update, authorized: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and type and all action with valid pin",
			resource:    Resource{ScopeId: "o_b", Pin: "mypin", Type: resource.Host},
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
			resource:    Resource{ScopeId: "o_a", Id: "anything", Type: resource.HostCatalog, Pin: "a_bar"},
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
			scopeGrants: commonGrants,
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
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.Update, authorized: true},
			},
			userId: "u_abcd1234",
		},
		{
			name:        "bad templated old account id",
			resource:    Resource{ScopeId: "o_c"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List},
				{action: action.Authenticate},
				{action: action.Delete},
			},
			accountId: fmt.Sprintf("%s_1234567890", intglobals.OldPasswordAccountPrefix),
		},
		{
			name:        "good templated old account id",
			resource:    Resource{ScopeId: "o_c", Id: fmt.Sprintf("%s_1234567890", intglobals.OldPasswordAccountPrefix)},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.ChangePassword, authorized: true},
				{action: action.Update},
			},
			accountId: fmt.Sprintf("%s_1234567890", intglobals.OldPasswordAccountPrefix),
		},
		{
			name:        "bad templated new account id",
			resource:    Resource{ScopeId: "o_c"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.List},
				{action: action.Authenticate},
				{action: action.Delete},
			},
			accountId: fmt.Sprintf("%s_1234567890", intglobals.NewPasswordAccountPrefix),
		},
		{
			name:        "good templated new account id",
			resource:    Resource{ScopeId: "o_c", Id: fmt.Sprintf("%s_1234567890", intglobals.NewPasswordAccountPrefix)},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.ChangePassword, authorized: true},
				{action: action.Update},
			},
			accountId: fmt.Sprintf("%s_1234567890", intglobals.NewPasswordAccountPrefix),
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
			resource:    Resource{ScopeId: "o_a", Id: "a_bar"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read, authorized: true},
				{action: action.ReadSelf, authorized: true},
			},
		},
		{
			name:        "read self only",
			resource:    Resource{ScopeId: "o_a", Id: "a_baz"},
			scopeGrants: commonGrants,
			actionsAuthorized: []actionAuthorized{
				{action: action.Read},
				{action: action.ReadSelf, authorized: true},
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
				result := acl.Allowed(test.resource, aa.action, false)
				assert.True(t, result.Authorized == aa.authorized, "action: %s, acl authorized: %t, test action authorized: %t", aa.action, acl.Allowed(test.resource, aa.action, false).Authorized, aa.authorized)
				assert.ElementsMatch(t, result.OutputFields.Fields(), aa.outputFields)
			}
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
