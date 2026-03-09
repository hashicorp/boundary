// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_OutputFields(t *testing.T) {
	t.Parallel()

	type input struct {
		name     string
		fields   []string
		startMap *OutputFields
		resMap   *OutputFields
		resStar  bool
	}
	tests := []input{
		{
			name:   "nil map, add nil",
			resMap: &OutputFields{},
		},
		{
			name:   "nil map, add empty fields",
			fields: []string{},
			resMap: &OutputFields{
				fields: map[string]bool{},
			},
		},
		{
			name:   "nil map, add fields",
			fields: []string{"id", "version"},
			resMap: &OutputFields{
				fields: map[string]bool{
					"id":      true,
					"version": true,
				},
			},
		},
		{
			name: "existing map, add nil",
			startMap: &OutputFields{
				fields: map[string]bool{
					"id":      true,
					"version": true,
				},
			},
			resMap: &OutputFields{
				fields: map[string]bool{
					"id":      true,
					"version": true,
				},
			},
		},
		{
			name: "existing with star, add nil",
			startMap: &OutputFields{
				fields: map[string]bool{
					"*": true,
				},
			},
			resMap: &OutputFields{
				fields: map[string]bool{
					"*": true,
				},
			},
			resStar: true,
		},
		{
			name:   "existing with star, add new",
			fields: []string{"id", "version"},
			startMap: &OutputFields{
				fields: map[string]bool{
					"*": true,
				},
			},
			resMap: &OutputFields{
				fields: map[string]bool{
					"*": true,
				},
			},
			resStar: true,
		},
		{
			name:   "existing without star, add new",
			fields: []string{"id", "version"},
			startMap: &OutputFields{
				fields: map[string]bool{
					"name": true,
				},
			},
			resMap: &OutputFields{
				fields: map[string]bool{
					"id":      true,
					"version": true,
					"name":    true,
				},
			},
		},
		{
			name:   "existing without star, add star",
			fields: []string{"id", "*"},
			startMap: &OutputFields{
				fields: map[string]bool{
					"name": true,
				},
			},
			resMap: &OutputFields{
				fields: map[string]bool{
					"*": true,
				},
			},
			resStar: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			out := test.startMap.AddFields(test.fields)
			assert.True(out.Has("*") == test.resStar)
			assert.Equal(test.resMap, out)
		})
	}
}

func Test_ACLOutputFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type input struct {
		name       string
		grants     []string
		resource   Resource
		action     action.Type
		fields     []string
		authorized bool
	}
	tests := []input{
		{
			name:       "default",
			resource:   Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			action:     action.Read,
			grants:     []string{"ids=u_bar;actions=read,update"},
			authorized: true,
		},
		{
			name:       "single value",
			resource:   Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants:     []string{"ids=u_bar;actions=read,update;output_fields=id"},
			action:     action.Read,
			fields:     []string{"id"},
			authorized: true,
		},
		{
			name:     "compound no overlap",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;actions=read,update;output_fields=id",
				"ids=*;type=host-catalog;actions=read,update;output_fields=version",
			},
			action:     action.Read,
			fields:     []string{"id"},
			authorized: true,
		},
		{
			name:     "compound",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;actions=read,update;output_fields=id",
				"ids=*;type=role;output_fields=version",
			},
			action:     action.Read,
			fields:     []string{"id", "version"},
			authorized: true,
		},
		{
			name:     "wildcard with type",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;actions=read,update;output_fields=read",
				"ids=*;type=role;output_fields=*",
			},
			action:     action.Read,
			fields:     []string{"*"},
			authorized: true,
		},
		{
			name:     "wildcard with wildcard type",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;actions=read,update;output_fields=read",
				"ids=*;type=*;output_fields=*",
			},
			action:     action.Read,
			fields:     []string{"*"},
			authorized: true,
		},
		{
			name:     "subaction exact",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;actions=read:self,update;output_fields=version",
			},
			action:     action.ReadSelf,
			fields:     []string{"version"},
			authorized: true,
		},
		{
			// If the action is a subaction, parent output fields will apply, in
			// addition to subaction. This matches authorization.
			name:     "subaction parent action",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;actions=read,update;output_fields=version",
				"ids=u_bar;actions=read:self;output_fields=id",
			},
			action:     action.ReadSelf,
			fields:     []string{"id", "version"},
			authorized: true,
		},
		{
			// The inverse isn't true. Similarly to authorization, if you have
			// specific output fields on a self action, they don't apply to
			// non-self actions. This is useful to allow more visibility to self
			// actions and less in the general case.
			name:     "subaction child action",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;actions=read:self,update;output_fields=version",
				"ids=u_bar;actions=read;output_fields=id",
			},
			action:     action.Read,
			fields:     []string{"id"},
			authorized: true,
		},
		{
			name:     "initial grant unauthorized with star",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;output_fields=*",
				"ids=u_bar;actions=delete;output_fields=id",
			},
			action:     action.Delete,
			fields:     []string{"*"},
			authorized: true,
		},
		{
			name:     "unauthorized id only",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Id: "u_bar", Type: resource.Role},
			grants: []string{
				"ids=u_bar;output_fields=name",
			},
			action: action.Delete,
			fields: []string{"name"},
		},
		{
			name:     "unauthorized type only",
			resource: Resource{ScopeId: "o_myorg", ParentScopeId: scope.Global.String(), Type: resource.Role},
			grants: []string{
				"type=role;output_fields=name",
			},
			action: action.List,
			fields: []string{"name"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var grants []Grant
			for _, g := range test.grants {
				grant, err := Parse(ctx, GrantTuple{RoleScopeId: "o_myorg", GrantScopeId: "o_myorg", Grant: g})
				require.NoError(t, err)
				grants = append(grants, grant)
			}
			acl := NewACL(grants...)
			results := acl.Allowed(test.resource, test.action, globals.AnonymousUserId, WithSkipAnonymousUserRestrictions(true))
			fields, _ := results.OutputFields.Fields()
			assert.ElementsMatch(t, fields, test.fields)
			assert.True(t, test.authorized == results.Authorized)
		})
	}
}

func Test_ACLSelfOrDefault(t *testing.T) {
	t.Parallel()

	type input struct {
		name   string
		input  *OutputFields
		output *OutputFields
		userId string
	}
	tests := []input{
		{
			name: "nil, no user ID, set but empty",
			output: &OutputFields{
				fields: map[string]bool{},
			},
		},
		{
			name: "nil, non anon id",
			output: &OutputFields{
				fields: map[string]bool{
					"*": true,
				},
			},
			userId: "u_abc123",
		},
		{
			name: "nil, anon id",
			output: &OutputFields{
				fields: map[string]bool{
					globals.IdField:                          true,
					globals.ScopeField:                       true,
					globals.ScopeIdField:                     true,
					globals.PluginField:                      true,
					globals.PluginIdField:                    true,
					globals.NameField:                        true,
					globals.DescriptionField:                 true,
					globals.TypeField:                        true,
					globals.IsPrimaryField:                   true,
					globals.PrimaryAuthMethodIdField:         true,
					globals.AuthorizedActionsField:           true,
					globals.AuthorizedCollectionActionsField: true,
				},
			},
			userId: globals.AnonymousUserId,
		},
		{
			name: "not nil",
			input: &OutputFields{
				fields: map[string]bool{
					"foo": true,
				},
			},
			output: &OutputFields{
				fields: map[string]bool{
					"foo": true,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.output, test.input.SelfOrDefaults(test.userId))
		})
	}
}
