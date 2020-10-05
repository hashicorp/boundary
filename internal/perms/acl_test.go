package perms

import (
	"testing"

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
	type actionAllowed struct {
		action  action.Type
		allowed bool
	}
	type input struct {
		name           string
		scopeGrants    []scopeGrant
		resource       Resource
		actionsAllowed []actionAllowed
		userId         string
		accountId      string
	}

	// A set of common grants to use in the following tests
	commonGrants := []scopeGrant{
		{
			scope: "o_a",
			grants: []string{
				"id=a_bar;actions=read,update",
				"type=host-catalog;actions=create",
				"type=target;actions=list",
				"id=*;type=host-set;actions=list,create",
			},
		},
		{
			scope: "o_b",
			grants: []string{
				"id=*;type=host-set;actions=list,create",
				"id=mypin;type=host;actions=*",
				"id=*;type=*;actions=authenticate",
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
			},
		},
	}

	// See acl.go for expected allowed formats. The goal here is to basically
	// test those, but also test a whole bunch of nonconforming values.
	tests := []input{
		{
			name:     "no grants",
			resource: Resource{ScopeId: "foo", Id: "bar", Type: resource.HostCatalog},
			actionsAllowed: []actionAllowed{
				{action: action.Create},
				{action: action.Read},
			},
		},
		{
			name:        "no overlap",
			resource:    Resource{ScopeId: "foo", Id: "bar", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Create},
				{action: action.Read},
			},
		},
		{
			name:        "top level create with type only",
			resource:    Resource{ScopeId: "o_a", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Create, allowed: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id no matching action",
			resource:    Resource{ScopeId: "o_a", Id: "a_foo", Type: resource.Role},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id and matching action",
			resource:    Resource{ScopeId: "o_a", Id: "a_bar"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Read, allowed: true},
				{action: action.Update, allowed: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and type and all action with valid pin",
			resource:    Resource{ScopeId: "o_b", Pin: "mypin", Type: resource.Host},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Read, allowed: true},
				{action: action.Update, allowed: true},
				{action: action.Delete, allowed: true},
			},
		},
		{
			name:        "matching scope and type and all action but bad pin",
			resource:    Resource{ScopeId: "o_b", Pin: "notmypin", Type: resource.Host},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Read},
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and id and some action",
			resource:    Resource{ScopeId: "o_b", Id: "myhost", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.List, allowed: true},
				{action: action.Create, allowed: true},
				{action: action.AddHosts},
			},
		},
		{
			name:        "matching scope and id and all action but bad specifier",
			resource:    Resource{ScopeId: "o_b", Id: "id_g"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Read},
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and not matching type",
			resource:    Resource{ScopeId: "o_a", Type: resource.HostCatalog},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Update},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope and matching type",
			resource:    Resource{ScopeId: "o_a", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.List, allowed: true},
				{action: action.Create, allowed: true},
				{action: action.Delete},
			},
		},
		{
			name:        "matching scope, type, action, random id and bad pin",
			resource:    Resource{ScopeId: "o_a", Id: "anything", Type: resource.HostCatalog, Pin: "a_bar"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Update},
				{action: action.Delete},
				{action: action.Read},
			},
		},
		{
			name:        "wrong scope and matching type",
			resource:    Resource{ScopeId: "o_bad", Type: resource.HostSet},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.List},
				{action: action.Create},
				{action: action.Delete},
			},
		},
		{
			name:        "any id",
			resource:    Resource{ScopeId: "o_b", Type: resource.AuthMethod},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.List},
				{action: action.Authenticate, allowed: true},
				{action: action.Delete},
			},
		},
		{
			name:        "bad templated user id",
			resource:    Resource{ScopeId: "o_c"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
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
			actionsAllowed: []actionAllowed{
				{action: action.Read, allowed: true},
				{action: action.Update, allowed: true},
			},
			userId: "u_abcd1234",
		},
		{
			name:        "bad templated account id",
			resource:    Resource{ScopeId: "o_c"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.List},
				{action: action.Authenticate},
				{action: action.Delete},
			},
			accountId: "apw_1234567890",
		},
		{
			name:        "good templated user id",
			resource:    Resource{ScopeId: "o_c", Id: "apw_1234567890"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.ChangePassword, allowed: true},
				{action: action.Update},
			},
			accountId: "apw_1234567890",
		},
		{
			name:        "all type",
			resource:    Resource{ScopeId: "o_d", Type: resource.Account},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: action.Create, allowed: true},
				{action: action.Update, allowed: true},
			},
			userId: "u_abcd1234",
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
			for _, aa := range test.actionsAllowed {
				assert.True(t, acl.Allowed(test.resource, aa.action).Allowed == aa.allowed)
			}
		})
	}
}
