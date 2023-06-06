// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package perms

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ActionParsingValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type input struct {
		name      string
		input     Grant
		errResult string
		result    Grant
	}

	tests := []input{
		{
			name:      "no actions",
			errResult: "perms.(Grant).parseAndValidateActions: missing actions: parameter violation: error #100",
		},
		{
			name: "empty action",
			input: Grant{
				actionsBeingParsed: []string{"create", "", "read"},
			},
			errResult: "perms.(Grant).parseAndValidateActions: empty action found: parameter violation: error #100",
		},
		{
			name: "empty action with output fields",
			input: Grant{
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"id": true,
					},
				},
			},
			result: Grant{
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"id": true,
					},
				},
			},
		},
		{
			name: "unknown action",
			input: Grant{
				actionsBeingParsed: []string{"create", "foobar", "read"},
			},
			errResult: `perms.(Grant).parseAndValidateActions: unknown action "foobar": parameter violation: error #100`,
		},
		{
			name: "all",
			input: Grant{
				actionsBeingParsed: []string{"*"},
			},
			result: Grant{
				actions: map[action.Type]bool{
					action.All: true,
				},
			},
		},
		{
			name: "all valid plus all",
			input: Grant{
				actionsBeingParsed: []string{"list", "create", "update", "*", "read", "delete", "authenticate", "authorize-session"},
			},
			errResult: `perms.(Grant).parseAndValidateActions: "*" cannot be specified with other actions: parameter violation: error #100`,
		},
		{
			name: "all valid",
			input: Grant{
				actionsBeingParsed: []string{"list", "create", "update", "read", "delete", "authenticate", "authorize-session"},
			},
			result: Grant{
				actions: map[action.Type]bool{
					action.List:             true,
					action.Create:           true,
					action.Update:           true,
					action.Read:             true,
					action.Delete:           true,
					action.Authenticate:     true,
					action.AuthorizeSession: true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.input.parseAndValidateActions(ctx)
			if test.errResult == "" {
				require.NoError(t, err)
				assert.Equal(t, test.result, test.input)
			} else {
				require.Error(t, err)
				assert.Equal(t, test.errResult, err.Error())
			}
		})
	}
}

func Test_ValidateType(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var g Grant
	for i := resource.Unknown; i <= resource.StorageBucket; i++ {
		g.typ = i
		if i == resource.Controller {
			assert.Error(t, g.validateType(ctx))
		} else {
			assert.NoError(t, g.validateType(ctx))
		}
	}
}

func Test_MarshalingAndCloning(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type input struct {
		name            string
		input           Grant
		jsonOutput      string
		canonicalString string
	}

	tests := []input{
		{
			name: "empty",
			input: Grant{
				scope: Scope{
					Type: scope.Org,
				},
			},
			jsonOutput:      `{}`,
			canonicalString: ``,
		},
		{
			name: "type and id",
			input: Grant{
				id: "baz",
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
			},
			jsonOutput:      `{"id":"baz","type":"group"}`,
			canonicalString: `id=baz;type=group`,
		},
		{
			name: "type and ids",
			input: Grant{
				ids: []string{"baz", "bop"},
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
			},
			jsonOutput:      `{"ids":["baz","bop"],"type":"group"}`,
			canonicalString: `ids=baz,bop;type=group`,
		},
		{
			name: "type and ids single id",
			input: Grant{
				ids: []string{"baz"},
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
			},
			jsonOutput:      `{"ids":["baz"],"type":"group"}`,
			canonicalString: `ids=baz;type=group`,
		},
		{
			name: "output fields id",
			input: Grant{
				id: "baz",
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"name":    true,
						"version": true,
						"id":      true,
					},
				},
			},
			jsonOutput:      `{"id":"baz","output_fields":["id","name","version"],"type":"group"}`,
			canonicalString: `id=baz;type=group;output_fields=id,name,version`,
		},
		{
			name: "output fields ids",
			input: Grant{
				ids: []string{"baz", "bop"},
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"name":    true,
						"version": true,
						"id":      true,
					},
				},
			},
			jsonOutput:      `{"ids":["baz","bop"],"output_fields":["id","name","version"],"type":"group"}`,
			canonicalString: `ids=baz,bop;type=group;output_fields=id,name,version`,
		},
		{
			name: "everything id",
			input: Grant{
				id: "baz",
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
				actionsBeingParsed: []string{"create", "read"},
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"name":    true,
						"version": true,
						"id":      true,
					},
				},
			},
			jsonOutput:      `{"actions":["create","read"],"id":"baz","output_fields":["id","name","version"],"type":"group"}`,
			canonicalString: `id=baz;type=group;actions=create,read;output_fields=id,name,version`,
		},
		{
			name: "everything ids",
			input: Grant{
				ids: []string{"baz", "bop"},
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
				actionsBeingParsed: []string{"create", "read"},
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"name":    true,
						"version": true,
						"ids":     true,
					},
				},
			},
			jsonOutput:      `{"actions":["create","read"],"ids":["baz","bop"],"output_fields":["ids","name","version"],"type":"group"}`,
			canonicalString: `ids=baz,bop;type=group;actions=create,read;output_fields=ids,name,version`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := test.input.MarshalJSON(ctx)
			require.NoError(t, err)
			assert.Equal(t, test.jsonOutput, string(output))
			assert.Equal(t, test.canonicalString, test.input.CanonicalString())
			assert.Equal(t, &test.input, test.input.clone())
		})
	}
}

func Test_Unmarshaling(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type input struct {
		name      string
		jsonInput string
		textInput string
		jsonErr   string
		textErr   string
		expected  Grant
	}

	tests := []input{
		{
			name:      "empty",
			expected:  Grant{},
			jsonInput: `{}`,
			textInput: ``,
			textErr:   `segment "" not formatted correctly, wrong number of equal signs`,
		},
		{
			name:      "bad json",
			jsonInput: `w329uf`,
			jsonErr:   "perms.(Grant).unmarshalJSON: error occurred during decode, encoding issue: error #303: invalid character 'w' looking for beginning of value",
		},
		{
			name:      "bad segment id",
			jsonInput: `{"id":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "id" as string: parameter violation: error #100`,
			textInput: `id=`,
			textErr:   `perms.(Grant).unmarshalText: segment "id=" not formatted correctly, missing value: parameter violation: error #100`,
		},
		{
			name:      "bad segment ids",
			jsonInput: `{"ids":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "ids" as array: parameter violation: error #100`,
			textInput: `ids=`,
			textErr:   `perms.(Grant).unmarshalText: segment "ids=" not formatted correctly, missing value: parameter violation: error #100`,
		},
		{
			name: "good id",
			expected: Grant{
				id: "foobar",
			},
			jsonInput: `{"id":"foobar"}`,
			textInput: `id=foobar`,
		},
		{
			name: "good ids",
			expected: Grant{
				ids: []string{"foobar"},
			},
			jsonInput: `{"ids":["foobar"]}`,
			textInput: `ids=foobar`,
		},
		{
			name:      "bad id",
			jsonInput: `{"id":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "id" as string: parameter violation: error #100`,
			textInput: `=id`,
			textErr:   `perms.(Grant).unmarshalText: segment "=id" not formatted correctly, missing key: parameter violation: error #100`,
		},
		{
			name:      "bad ids",
			jsonInput: `{"ids":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "ids" as array: parameter violation: error #100`,
			textInput: `=ids`,
			textErr:   `perms.(Grant).unmarshalText: segment "=ids" not formatted correctly, missing key: parameter violation: error #100`,
		},
		{
			name: "good type",
			expected: Grant{
				typ: resource.HostCatalog,
			},
			jsonInput: `{"type":"host-catalog"}`,
			textInput: `type=host-catalog`,
		},
		{
			name:      "bad type",
			jsonInput: `{"type":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "type" as string: parameter violation: error #100`,
			textInput: `type=host-catalog=id`,
			textErr:   `perms.(Grant).unmarshalText: segment "type=host-catalog=id" not formatted correctly, wrong number of equal signs: parameter violation: error #100`,
		},
		{
			name: "good output fields id",
			expected: Grant{
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"name":    true,
						"version": true,
						"id":      true,
					},
				},
			},
			jsonInput: `{"output_fields":["id","name","version"]}`,
			textInput: `output_fields=id,version,name`,
		},
		{
			name: "good output fields ids",
			expected: Grant{
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"name":    true,
						"version": true,
						"ids":     true,
					},
				},
			},
			jsonInput: `{"output_fields":["ids","name","version"]}`,
			textInput: `output_fields=ids,version,name`,
		},
		{
			name:      "bad output fields id",
			jsonInput: `{"output_fields":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "output_fields" as array: parameter violation: error #100`,
			textInput: `output_fields=id=version,name`,
			textErr:   `perms.(Grant).unmarshalText: segment "output_fields=id=version,name" not formatted correctly, wrong number of equal signs: parameter violation: error #100`,
		},
		{
			name:      "bad output fields ids",
			jsonInput: `{"output_fields":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "output_fields" as array: parameter violation: error #100`,
			textInput: `output_fields=ids=version,name`,
			textErr:   `perms.(Grant).unmarshalText: segment "output_fields=ids=version,name" not formatted correctly, wrong number of equal signs: parameter violation: error #100`,
		},
		{
			name: "good actions",
			expected: Grant{
				actionsBeingParsed: []string{"create", "read"},
			},
			jsonInput: `{"actions":["create","read"]}`,
			textInput: `actions=create,read`,
		},
		{
			name:      "bad actions",
			jsonInput: `{"actions":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "actions" as array: parameter violation: error #100`,
			textInput: `type=host-catalog=id`,
			textErr:   `perms.(Grant).unmarshalText: segment "type=host-catalog=id" not formatted correctly, wrong number of equal signs: parameter violation: error #100`,
		},
		{
			name:      "empty actions",
			jsonInput: `{"actions":[""]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: empty action found: parameter violation: error #100`,
			textInput: `actions=,`,
			textErr:   `perms.(Grant).unmarshalText: empty action found: parameter violation: error #100`,
		},
		{
			name:      "bad json action",
			jsonInput: `{"actions":[1, true]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret 1 in actions array as string: parameter violation: error #100`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			var g Grant
			if test.jsonInput != "" {
				err := g.unmarshalJSON(ctx, []byte(test.jsonInput))
				if test.jsonErr != "" {
					require.Error(err)
					assert.Equal(test.jsonErr, err.Error())
				} else {
					require.NoError(err)
					assert.Equal(test.expected, g)
				}
			}
			g = Grant{}
			if test.textInput != "" {
				err := g.unmarshalText(ctx, test.textInput)
				if test.textErr != "" {
					require.Error(err)
					assert.Equal(test.textErr, err.Error())
				} else {
					require.NoError(err)
					assert.Equal(test.expected, g)
				}
			}
		})
	}
}

func Test_Parse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type input struct {
		name          string
		input         string
		userId        string
		accountId     string
		err           string
		scopeOverride string
		expected      Grant
	}

	tests := []input{
		{
			name: "empty",
			err:  `perms.Parse: missing grant string: parameter violation: error #100`,
		},
		{
			name:  "bad json",
			input: "{2:193}",
			err:   `perms.Parse: unable to parse JSON grant string: perms.(Grant).unmarshalJSON: error occurred during decode, encoding issue: error #303: invalid character '2' looking for beginning of object key string`,
		},
		{
			name:  "bad text",
			input: "id=foo=bar",
			err:   `perms.Parse: unable to parse grant string: perms.(Grant).unmarshalText: segment "id=foo=bar" not formatted correctly, wrong number of equal signs: parameter violation: error #100`,
		},
		{
			name:  "bad type",
			input: "ids=s_foobar;type=barfoo;actions=read",
			err:   `perms.Parse: unable to parse grant string: perms.(Grant).unmarshalText: unknown type specifier "barfoo": parameter violation: error #100`,
		},
		{
			name:  "bad actions",
			input: "ids=hcst_foobar;type=host-catalog;actions=createread",
			err:   `perms.Parse: perms.(Grant).parseAndValidateActions: unknown action "createread": parameter violation: error #100`,
		},
		{
			name:  "bad id type",
			input: "id=foobar;actions=read",
			err:   `perms.Parse: parsed grant string "id=foobar;actions=read" contains an id "foobar" of an unknown resource type: parameter violation: error #100`,
		},
		{
			name:  "bad ids type first position",
			input: "ids=foobar,hcst_foobar;actions=read",
			err:   `perms.Parse: input grant string "ids=foobar,hcst_foobar;actions=read" contains ids of differently-typed resources: parameter violation: error #100`,
		},
		{
			name:  "bad ids type second position",
			input: "ids=hcst_foobar,foobar;actions=read",
			err:   `perms.Parse: input grant string "ids=hcst_foobar,foobar;actions=read" contains ids of differently-typed resources: parameter violation: error #100`,
		},
		{
			name:  "bad create action for ids",
			input: "ids=u_foobar;actions=create",
			err:   `perms.Parse: parsed grant string "ids=u_foobar;actions=create" contains create or list action in a format that does not allow these: parameter violation: error #100`,
		},
		{
			name:  "bad create action for ids with other perms",
			input: "ids=u_foobar;actions=read,create",
			err:   `perms.Parse: parsed grant string "ids=u_foobar;actions=create,read" contains create or list action in a format that does not allow these: parameter violation: error #100`,
		},
		{
			name:  "bad list action for id",
			input: "id=u_foobar;actions=list",
			err:   `perms.Parse: parsed grant string "id=u_foobar;actions=list" contains create or list action in a format that does not allow these: parameter violation: error #100`,
		},
		{
			name:  "bad list action for type with other perms",
			input: "type=host-catalog;actions=list,read",
			err:   `perms.Parse: parsed grant string "type=host-catalog;actions=list,read" contains non-create or non-list action in a format that only allows these: parameter violation: error #100`,
		},
		{
			name:  "wildcard id and actions without collection",
			input: "id=*;actions=read",
			err:   `perms.Parse: parsed grant string "id=*;actions=read" contains wildcard id and no specified type: parameter violation: error #100`,
		},
		{
			name:  "wildcard ids and actions without collection",
			input: "ids=*;actions=read",
			err:   `perms.Parse: parsed grant string "ids=*;actions=read" contains wildcard id and no specified type: parameter violation: error #100`,
		},
		{
			name:  "wildcard id and actions with list",
			input: "id=*;actions=read,list",
			err:   `perms.Parse: parsed grant string "id=*;actions=list,read" contains wildcard id and no specified type: parameter violation: error #100`,
		},
		{
			name:  "wildcard ids and actions with list",
			input: "ids=*;actions=read,list",
			err:   `perms.Parse: parsed grant string "ids=*;actions=list,read" contains wildcard id and no specified type: parameter violation: error #100`,
		},
		{
			name:  "wildcard type with no ids",
			input: "type=*;actions=read,list",
			err:   `perms.Parse: parsed grant string "type=*;actions=list,read" contains wildcard type with no id value: parameter violation: error #100`,
		},
		{
			name:  "mixed wildcard and non wildcard ids first position",
			input: "ids=*,u_foobar;actions=read,list",
			err:   `perms.Parse: input grant string "ids=*,u_foobar;actions=read,list" contains both wildcard and non-wildcard values in "ids" field: parameter violation: error #100`,
		},
		{
			name:  "mixed wildcard and non wildcard ids second position",
			input: "ids=u_foobar,*;actions=read,list",
			err:   `perms.Parse: input grant string "ids=u_foobar,*;actions=read,list" contains both wildcard and non-wildcard values in "ids" field: parameter violation: error #100`,
		},
		{
			name:  "empty ids and type",
			input: "actions=create",
			err:   `perms.Parse: parsed grant string "actions=create" contains no id or type: parameter violation: error #100`,
		},
		{
			name:  "wildcard type non child id",
			input: "id=ttcp_1234567890;type=*;actions=create",
			err:   `perms.Parse: parsed grant string "id=ttcp_1234567890;type=*;actions=create" contains an id that does not support child types: parameter violation: error #100`,
		},
		{
			name:  "wildcard type non child ids first position",
			input: "ids=ttcp_1234567890,ttcp_1234567890;type=*;actions=create",
			err:   `perms.Parse: parsed grant string "ids=ttcp_1234567890,ttcp_1234567890;type=*;actions=create" contains an id that does not support child types: parameter violation: error #100`,
		},
		{
			name:  "wildcard type non child ids second position",
			input: "ids=ttcp_1234567890,ttcp_1234567890;type=*;actions=create",
			err:   `perms.Parse: parsed grant string "ids=ttcp_1234567890,ttcp_1234567890;type=*;actions=create" contains an id that does not support child types: parameter violation: error #100`,
		},
		{
			name:  "specified resource type non child id",
			input: "id=hcst_1234567890;type=account;actions=read",
			err:   `perms.Parse: parsed grant string "id=hcst_1234567890;type=account;actions=read" contains type account that is not a child type of the type (host-catalog) of the specified id: parameter violation: error #100`,
		},
		{
			name:  "specified resource type non child ids first position",
			input: "ids=hcst_1234567890,hcst_1234567890;type=account;actions=read",
			err:   `perms.Parse: parsed grant string "ids=hcst_1234567890,hcst_1234567890;type=account;actions=read" contains type account that is not a child type of the type (host-catalog) of the specified id: parameter violation: error #100`,
		},
		{
			name:  "specified resource type non child ids second position",
			input: "ids=hcst_1234567890,hcst_1234567890;type=account;actions=read",
			err:   `perms.Parse: parsed grant string "ids=hcst_1234567890,hcst_1234567890;type=account;actions=read" contains type account that is not a child type of the type (host-catalog) of the specified id: parameter violation: error #100`,
		},
		{
			name:  "no id with one bad action",
			input: "type=host-set;actions=read",
			err:   `perms.Parse: parsed grant string "type=host-set;actions=read" contains non-create or non-list action in a format that only allows these: parameter violation: error #100`,
		},
		{
			name:  "no id with two bad action",
			input: "type=host-set;actions=read,create",
			err:   `perms.Parse: parsed grant string "type=host-set;actions=create,read" contains non-create or non-list action in a format that only allows these: parameter violation: error #100`,
		},
		{
			name:  "no id with three bad action",
			input: "type=host-set;actions=list,read,create",
			err:   `perms.Parse: parsed grant string "type=host-set;actions=create,list,read" contains non-create or non-list action in a format that only allows these: parameter violation: error #100`,
		},
		{
			name:  "empty output fields",
			input: "id=*;type=*;actions=read,list;output_fields=",
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "*",
				typ: resource.All,
				actions: map[action.Type]bool{
					action.Read: true,
					action.List: true,
				},
				OutputFields: &OutputFields{
					fields: make(map[string]bool),
				},
			},
		},
		{
			name:  "empty output fields json",
			input: `{"id": "*", "type": "*", "actions": ["read", "list"], "output_fields": []}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "*",
				typ: resource.All,
				actions: map[action.Type]bool{
					action.Read: true,
					action.List: true,
				},
				OutputFields: &OutputFields{
					fields: make(map[string]bool),
				},
			},
		},
		{
			name:  "wildcard id and type and actions with list",
			input: "id=*;type=*;actions=read,list",
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "*",
				typ: resource.All,
				actions: map[action.Type]bool{
					action.Read: true,
					action.List: true,
				},
			},
		},
		{
			name:  "wildcard ids and type and actions with list",
			input: "ids=*;type=*;actions=read,list",
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				ids: []string{"*"},
				typ: resource.All,
				actions: map[action.Type]bool{
					action.Read: true,
					action.List: true,
				},
			},
		},
		{
			name:  "good json type",
			input: `{"type":"host-catalog","actions":["create"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				typ: resource.HostCatalog,
				actions: map[action.Type]bool{
					action.Create: true,
				},
			},
		},
		{
			name:  "good json id",
			input: `{"id":"u_foobar","actions":["read"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "u_foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good json ids",
			input: `{"ids":["hcst_foobar", "hcst_foobaz"],"actions":["read"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				ids: []string{"hcst_foobar", "hcst_foobaz"},
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good json output fields id",
			input: `{"id":"u_foobar","actions":["read"],"output_fields":["version","id","name"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "u_foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"version": true,
						"id":      true,
						"name":    true,
					},
				},
			},
		},
		{
			name:  "good json output fields ids",
			input: `{"ids":["u_foobar"],"actions":["read"],"output_fields":["version","ids","name"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				ids: []string{"u_foobar"},
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"version": true,
						"ids":     true,
						"name":    true,
					},
				},
			},
		},
		{
			name:  "good json output fields no action",
			input: `{"id":"u_foobar","output_fields":["version","id","name"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "u_foobar",
				typ: resource.Unknown,
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"version": true,
						"id":      true,
						"name":    true,
					},
				},
			},
		},
		{
			name:  "good text type",
			input: `type=host-catalog;actions=create`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				typ: resource.HostCatalog,
				actions: map[action.Type]bool{
					action.Create: true,
				},
			},
		},
		{
			name:  "good text id",
			input: `id=u_foobar;actions=read`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "u_foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good text ids",
			input: `ids=hcst_foobar,hcst_foobaz;actions=read`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				ids: []string{"hcst_foobar", "hcst_foobaz"},
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good output fields id",
			input: `id=u_foobar;actions=read;output_fields=version,id,name`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "u_foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"version": true,
						"id":      true,
						"name":    true,
					},
				},
			},
		},
		{
			name:  "good output fields ids",
			input: `ids=hcst_foobar,hcst_foobaz;actions=read;output_fields=version,ids,name`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				ids: []string{"hcst_foobar", "hcst_foobaz"},
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
				OutputFields: &OutputFields{
					fields: map[string]bool{
						"version": true,
						"ids":     true,
						"name":    true,
					},
				},
			},
		},
		{
			name:          "default project scope",
			input:         `id=hcst_foobar;actions=read`,
			scopeOverride: "p_1234",
			expected: Grant{
				scope: Scope{
					Id:   "p_1234",
					Type: scope.Project,
				},
				id:  "hcst_foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:          "default org scope",
			input:         `id=acctpw_foobar;actions=read`,
			scopeOverride: "o_1234",
			expected: Grant{
				scope: Scope{
					Id:   "o_1234",
					Type: scope.Org,
				},
				id:  "acctpw_foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:          "default global scope",
			input:         `id=acctpw_foobar;actions=read`,
			scopeOverride: "global",
			expected: Grant{
				scope: Scope{
					Id:   "global",
					Type: scope.Global,
				},
				id:  "acctpw_foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:   "bad user id template",
			input:  `id={{superman}};actions=create,read`,
			userId: "u_abcd1234",
			err:    `perms.Parse: unknown template "{{superman}}" in grant "id" value: parameter violation: error #100`,
		},
		{
			name:   "bad user ids template",
			input:  `ids={{superman}};actions=create,read`,
			userId: "u_abcd1234",
			err:    `perms.Parse: unknown template "{{superman}}" in grant "ids" value: parameter violation: error #100`,
		},
		{
			name:   "good user id template",
			input:  `id={{    user.id}};actions=read,update`,
			userId: "u_abcd1234",
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id: "u_abcd1234",
				actions: map[action.Type]bool{
					action.Update: true,
					action.Read:   true,
				},
			},
		},
		{
			name:      "bad old account id template",
			input:     `id={{superman}};actions=read`,
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
			err:       `perms.Parse: unknown template "{{superman}}" in grant "id" value: parameter violation: error #100`,
		},
		{
			name:      "bad old account ids template",
			input:     `ids={{superman}};actions=read`,
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
			err:       `perms.Parse: unknown template "{{superman}}" in grant "ids" value: parameter violation: error #100`,
		},
		{
			name:      "bad new account id template",
			input:     `id={{superman}};actions=read`,
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
			err:       `perms.Parse: unknown template "{{superman}}" in grant "id" value: parameter violation: error #100`,
		},
		{
			name:      "good old account id template",
			input:     `id={{    account.id}};actions=update,read`,
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
				actions: map[action.Type]bool{
					action.Update: true,
					action.Read:   true,
				},
			},
		},
		{
			name:      "good new account id template",
			input:     `id={{    account.id}};actions=update,read`,
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
				actions: map[action.Type]bool{
					action.Update: true,
					action.Read:   true,
				},
			},
		},
		{
			name:      "good ids template",
			input:     `ids={{    user.id}},{{    account.id}};actions=read,update`,
			userId:    "u_abcd1234",
			accountId: fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				ids: []string{"u_abcd1234", "acctpw_1234567890"},
				actions: map[action.Type]bool{
					action.Update: true,
					action.Read:   true,
				},
			},
		},
	}

	_, err := Parse(ctx, "", "")
	require.Error(t, err)
	assert.Equal(t, "perms.Parse: missing grant string: parameter violation: error #100", err.Error())

	_, err = Parse(ctx, "", "{}")
	require.Error(t, err)
	assert.Equal(t, "perms.Parse: missing scope id: parameter violation: error #100", err.Error())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			scope := "o_scope"
			if test.scopeOverride != "" {
				scope = test.scopeOverride
			}
			grant, err := Parse(ctx, scope, test.input, WithUserId(test.userId), WithAccountId(test.accountId))
			if test.err != "" {
				require.Error(err)
				assert.Equal(test.err, err.Error())
			} else {
				require.NoError(err)
				assert.Equal(test.expected, grant)
			}
		})
	}
}

func TestHasActionOrSubaction(t *testing.T) {
	tests := []struct {
		name string
		base []action.Type
		act  action.Type
		want bool
	}{
		{
			name: "no actions",
			base: []action.Type{},
			act:  action.Read,
		},
		{
			name: "has direct action",
			base: []action.Type{action.Cancel, action.Read},
			act:  action.Read,
			want: true,
		},
		{
			name: "has parent action",
			base: []action.Type{action.Cancel, action.ReadSelf},
			act:  action.Read,
			want: true,
		},
		{
			name: "has direct sub action",
			base: []action.Type{action.Cancel, action.ReadSelf},
			act:  action.ReadSelf,
			want: true,
		},
		{
			name: "has sub action needs parent",
			base: []action.Type{action.Cancel, action.Read},
			act:  action.ReadSelf,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := Grant{
				actions: make(map[action.Type]bool),
			}
			for _, act := range tt.base {
				g.actions[act] = true
			}
			assert.Equal(t, tt.want, g.hasActionOrSubaction(tt.act))
		})
	}
}

func FuzzParse(f *testing.F) {
	ctx := context.Background()

	f.Add("type=host-catalog;actions=create")
	f.Add("type=*;actions=*")
	f.Add("id=*;type=*;actions=*")
	f.Add("ids=*;type=*;actions=*")
	f.Add("id=*;type=*;actions=read,list")
	f.Add("ids=*;type=*;actions=read,list")
	f.Add("id=foobar;actions=read;output_fields=version,id,name")
	f.Add("ids=foobar,foobaz;actions=read;output_fields=version,id,name")
	f.Add("id={{account.id}};actions=update,read")
	f.Add("ids={{account.id}},{{user.id}};actions=update,read")
	f.Add(`{"id":"foobar","type":"host-catalog","actions":["create"]}`)
	f.Add(`{"ids":["foobar"],"type":"host-catalog","actions":["create"]}`)

	f.Fuzz(func(t *testing.T, grant string) {
		g, err := Parse(ctx, "global", grant, WithSkipFinalValidation(true))
		if err != nil {
			return
		}
		g2, err := Parse(ctx, "global", g.CanonicalString(), WithSkipFinalValidation(true))
		if err != nil {
			t.Fatal("Failed to parse canonical string:", err)
		}
		if g.CanonicalString() != g2.CanonicalString() {
			t.Errorf("grant roundtrip failed, input %q, output %q", g.CanonicalString(), g2.CanonicalString())
		}
		jsonBytes, err := g.MarshalJSON(ctx)
		if err != nil {
			t.Error("Failed to marshal JSON:", err)
		}
		g3, err := Parse(ctx, "global", string(jsonBytes), WithSkipFinalValidation(true))
		if err != nil {
			t.Fatal("Failed to parse json string:", err)
		}
		if g.CanonicalString() != g3.CanonicalString() {
			t.Errorf("grant JSON roundtrip failed, input %q, output %q", g.CanonicalString(), g3.CanonicalString())
		}
	})
}
