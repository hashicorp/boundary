package perms

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
)

func Test_ACLAllowed(t *testing.T) {
	t.Parallel()

	type scopeGrant struct {
		scope  Scope
		grants []string
	}
	type actionAllowed struct {
		action  iam.Action
		allowed bool
	}
	type input struct {
		name           string
		scopeGrants    []scopeGrant
		resource       Resource
		actionsAllowed []actionAllowed
	}

	// A set of common grants to use in the following tests
	commonGrants := []scopeGrant{
		{
			scope: Scope{Type: iam.OrganizationScope, Id: "org_a"},
			grants: []string{
				"id=a_bar;actions=read,update",
				"id=a_foo;type=host-catalog;actions=update,delete",
				"type=host-set;actions=list,create",
			},
		},
		{
			scope: Scope{Type: iam.OrganizationScope, Id: "org_b"},
			grants: []string{
				"project=proj_x;type=host-set;actions=list,create",
				"type=host;actions=all",
			},
		},
	}

	// See acl.go for expected allowed formats. The goal here is to basically
	// test those, but also test a whole bunch of nonconforming values.
	tests := []input{
		{
			name:     "no grants",
			resource: Resource{ScopeId: "foo", Id: "bar", Type: "typ"},
			actionsAllowed: []actionAllowed{
				{action: iam.ActionCreate},
				{action: iam.ActionRead},
			},
		},
		{
			name:        "no overlap",
			resource:    Resource{ScopeId: "foo", Id: "bar", Type: "typ"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionCreate},
				{action: iam.ActionRead},
			},
		},
		{
			name:        "matching scope and id no matching action",
			resource:    Resource{ScopeId: "org_a", Id: "a_foo"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionUpdate},
				{action: iam.ActionDelete},
			},
		},
		{
			name:        "matching scope and id and matching action",
			resource:    Resource{ScopeId: "org_a", Id: "a_bar"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionRead, allowed: true},
				{action: iam.ActionUpdate, allowed: true},
				{action: iam.ActionDelete},
			},
		},
		{
			name:        "matching scope and id and all action",
			resource:    Resource{ScopeId: "org_b", Type: "host"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionRead, allowed: true},
				{action: iam.ActionUpdate, allowed: true},
				{action: iam.ActionDelete, allowed: true},
			},
		},
		{
			name:        "matching scope and id and all action but bad specifier",
			resource:    Resource{ScopeId: "org_b", Id: "id_g"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionRead},
				{action: iam.ActionUpdate},
				{action: iam.ActionDelete},
			},
		},
		{
			name:        "matching scope and not matching type",
			resource:    Resource{ScopeId: "org_a", Type: "host-catalog"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionUpdate},
				{action: iam.ActionDelete},
			},
		},
		{
			name:        "matching scope and matching type",
			resource:    Resource{ScopeId: "org_a", Type: "host-set"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionList, allowed: true},
				{action: iam.ActionCreate, allowed: true},
				{action: iam.ActionDelete},
			},
		},
		{
			name:        "matching scope, type, action, bad pin",
			resource:    Resource{ScopeId: "org_a", Id: "a_foo", Type: "host-catalog"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionUpdate},
				{action: iam.ActionDelete},
				{action: iam.ActionRead},
			},
		},
		{
			name:        "matching scope, type, action, random id and bad pin",
			resource:    Resource{ScopeId: "org_a", Id: "anything", Type: "host-catalog", Pin: "a_bar"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionUpdate},
				{action: iam.ActionDelete},
				{action: iam.ActionRead},
			},
		},
		{
			name:        "matching scope, type, action, random id and good pin",
			resource:    Resource{ScopeId: "org_a", Id: "anything", Type: "host-catalog", Pin: "a_foo"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionUpdate, allowed: true},
				{action: iam.ActionDelete, allowed: true},
				{action: iam.ActionRead},
			},
		},
		{
			name:        "wrong scope and matching type",
			resource:    Resource{ScopeId: "org_bad", Type: "host-set"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionList},
				{action: iam.ActionCreate},
				{action: iam.ActionDelete},
			},
		},
		{
			name:        "cross project, bad project",
			resource:    Resource{ScopeId: "proj_y", Type: "host-set"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionList},
				{action: iam.ActionCreate},
				{action: iam.ActionDelete},
			},
		},
		{
			name:        "cross project, good project",
			resource:    Resource{ScopeId: "proj_x", Type: "host-set"},
			scopeGrants: commonGrants,
			actionsAllowed: []actionAllowed{
				{action: iam.ActionList, allowed: true},
				{action: iam.ActionCreate, allowed: true},
				{action: iam.ActionDelete},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var grants []Grant
			for _, sg := range test.scopeGrants {
				scope := sg.scope
				for _, g := range sg.grants {
					grant, err := ParseGrantString(scope, g)
					assert.NoError(t, err)
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
