// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
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
	for i := resource.Unknown; i <= resource.Alias; i++ {
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

	type input struct {
		name            string
		input           Grant
		jsonOutput      string
		canonicalString string
	}

	tests := []input{
		{
			name:            "empty",
			jsonOutput:      `{}`,
			canonicalString: ``,
		},
		{
			name: "type and id",
			input: Grant{
				id:  "baz",
				typ: resource.Group,
			},
			jsonOutput:      `{"id":"baz","type":"group"}`,
			canonicalString: `id=baz;type=group`,
		},
		{
			name: "type and ids",
			input: Grant{
				ids: []string{"baz", "bop"},
				typ: resource.Group,
			},
			jsonOutput:      `{"ids":["baz","bop"],"type":"group"}`,
			canonicalString: `ids=baz,bop;type=group`,
		},
		{
			name: "type and ids single id",
			input: Grant{
				ids: []string{"baz"},
				typ: resource.Group,
			},
			jsonOutput:      `{"ids":["baz"],"type":"group"}`,
			canonicalString: `ids=baz;type=group`,
		},
		{
			name: "output fields id",
			input: Grant{
				id:  "baz",
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
				id:  "baz",
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
			output, err := test.input.MarshalJSON()
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
			name:      "bad segment id comma",
			jsonInput: `{"id":","}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
			textInput: `id=,`,
			textErr:   `perms.(Grant).unmarshalText: ID cannot contain a comma: parameter violation: error #100`,
		},
		{
			name:      "bad segment id start with comma",
			jsonInput: `{"id":",something"}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
			textInput: `id=,something`,
			textErr:   `perms.(Grant).unmarshalText: ID cannot contain a comma: parameter violation: error #100`,
		},
		{
			name:      "bad segment id with comma",
			jsonInput: `{"id":"some,thing"}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
			textInput: `id=some,thing`,
			textErr:   `perms.(Grant).unmarshalText: ID cannot contain a comma: parameter violation: error #100`,
		},
		{
			name:      "bad segment id end with comma",
			jsonInput: `{"id":"something,"}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
			textInput: `id=something,`,
			textErr:   `perms.(Grant).unmarshalText: ID cannot contain a comma: parameter violation: error #100`,
		},
		{
			name:      "bad segment ids",
			jsonInput: `{"ids":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "ids" as array: parameter violation: error #100`,
			textInput: `ids=`,
			textErr:   `perms.(Grant).unmarshalText: segment "ids=" not formatted correctly, missing value: parameter violation: error #100`,
		},
		{
			name:      "empty segment ids",
			jsonInput: `{"ids":[""]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: empty ID provided: parameter violation: error #100`,
			textInput: `ids=,`,
			textErr:   `perms.(Grant).unmarshalText: empty ID provided: parameter violation: error #100`,
		},
		{
			name:      "segment ids comma",
			jsonInput: `{"ids":[","]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids starting with comma",
			jsonInput: `{"ids":[",something"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids with comma",
			jsonInput: `{"ids":["some,thing"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids ending with comma",
			jsonInput: `{"ids":["something,"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids semicolon",
			jsonInput: `{"ids":[","]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids starting with semicolon",
			jsonInput: `{"ids":[";something"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids with semicolon",
			jsonInput: `{"ids":["some;thing"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids ending with semicolon",
			jsonInput: `{"ids":["something;"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids equals sign",
			jsonInput: `{"ids":["="]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids starting with equals sign",
			jsonInput: `{"ids":["=something"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids with equals sign",
			jsonInput: `{"ids":["some=thing"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids ending with equals sign",
			jsonInput: `{"ids":["something="]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
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
			name:      "bad output fields comma",
			jsonInput: `{"output_fields":[","]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: output fields cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "output fields starting with comma",
			jsonInput: `{"output_fields":[",something"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: output fields cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "output fields with comma",
			jsonInput: `{"output_fields":["some,thing"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: output fields cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "output fields ending with comma",
			jsonInput: `{"output_fields":["something,"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: output fields cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids semicolon",
			jsonInput: `{"ids":[";"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids starting with semicolon",
			jsonInput: `{"ids":[";something"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids with semicolon",
			jsonInput: `{"ids":["some;thing"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids ending with semicolon",
			jsonInput: `{"ids":["something;"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids equals sign",
			jsonInput: `{"ids":["="]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids starting with equals sign",
			jsonInput: `{"ids":["=something"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids with equals sign",
			jsonInput: `{"ids":["some=thing"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment ids ending with equals sign",
			jsonInput: `{"ids":["something="]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: ID cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
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
		{
			name:      "segment actions comma",
			jsonInput: `{"actions":[","]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: action cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment actions starting with comma",
			jsonInput: `{"actions":[",something"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: action cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment actions with comma",
			jsonInput: `{"actions":["some,thing"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: action cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
		},
		{
			name:      "segment actions ending with comma",
			jsonInput: `{"actions":["something,"]}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: action cannot contain a comma, semicolon or equals sign: parameter violation: error #100`,
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
			name:  "empty output fields",
			input: "id=*;type=*;actions=read,list;output_fields=",
			expected: Grant{
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "*",
				typ:          resource.All,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "*",
				typ:          resource.All,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "*",
				typ:          resource.All,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				ids:          []string{"*"},
				typ:          resource.All,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				typ:          resource.HostCatalog,
				actions: map[action.Type]bool{
					action.Create: true,
				},
			},
		},
		{
			name:  "good json id",
			input: `{"id":"u_foobar","actions":["read"]}`,
			expected: Grant{
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "u_foobar",
				typ:          resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good json ids",
			input: `{"ids":["hcst_foobar", "hcst_foobaz"],"actions":["read"]}`,
			expected: Grant{
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				ids:          []string{"hcst_foobar", "hcst_foobaz"},
				typ:          resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good json output fields id",
			input: `{"id":"u_foobar","actions":["read"],"output_fields":["version","id","name"]}`,
			expected: Grant{
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "u_foobar",
				typ:          resource.Unknown,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				ids:          []string{"u_foobar"},
				typ:          resource.Unknown,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "u_foobar",
				typ:          resource.Unknown,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				typ:          resource.HostCatalog,
				actions: map[action.Type]bool{
					action.Create: true,
				},
			},
		},
		{
			name:  "good text id",
			input: `id=u_foobar;actions=read`,
			expected: Grant{
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "u_foobar",
				typ:          resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good text ids",
			input: `ids=hcst_foobar,hcst_foobaz;actions=read`,
			expected: Grant{
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				ids:          []string{"hcst_foobar", "hcst_foobaz"},
				typ:          resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:  "good output fields id",
			input: `id=u_foobar;actions=read;output_fields=version,id,name`,
			expected: Grant{
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "u_foobar",
				typ:          resource.Unknown,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				ids:          []string{"hcst_foobar", "hcst_foobaz"},
				typ:          resource.Unknown,
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
				roleScopeId:  "p_1234",
				grantScopeId: "p_1234",
				id:           "hcst_foobar",
				typ:          resource.Unknown,
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
				roleScopeId:  "o_1234",
				grantScopeId: "o_1234",
				id:           "acctpw_foobar",
				typ:          resource.Unknown,
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
				roleScopeId:  "global",
				grantScopeId: "global",
				id:           "acctpw_foobar",
				typ:          resource.Unknown,
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           "u_abcd1234",
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           fmt.Sprintf("%s_1234567890", globals.PasswordAccountPreviousPrefix),
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				id:           fmt.Sprintf("%s_1234567890", globals.PasswordAccountPrefix),
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
				roleScopeId:  "o_scope",
				grantScopeId: "o_scope",
				ids:          []string{"u_abcd1234", "acctpw_1234567890"},
				actions: map[action.Type]bool{
					action.Update: true,
					action.Read:   true,
				},
			},
		},
	}

	_, err := Parse(ctx, GrantTuple{RoleScopeId: "", GrantScopeId: "", Grant: ""})
	require.Error(t, err)
	assert.Equal(t, "perms.Parse: missing grant string: parameter violation: error #100", err.Error())

	_, err = Parse(ctx, GrantTuple{RoleScopeId: "", GrantScopeId: "", Grant: "{}"})
	require.Error(t, err)
	assert.Equal(t, "perms.Parse: missing role scope id: parameter violation: error #100", err.Error())

	_, err = Parse(ctx, GrantTuple{RoleScopeId: "p_abcd", GrantScopeId: "", Grant: "{}"})
	require.Error(t, err)
	assert.Equal(t, "perms.Parse: missing grant scope id: parameter violation: error #100", err.Error())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			scope := "o_scope"
			if test.scopeOverride != "" {
				scope = test.scopeOverride
			}
			grant, err := Parse(ctx, GrantTuple{RoleScopeId: scope, GrantScopeId: scope, Grant: test.input}, WithUserId(test.userId), WithAccountId(test.accountId))
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

func Test_HasNoGrants(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	var gt GrantTuples

	hash, err := gt.GrantHash(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, hash)
}

func FuzzParse(f *testing.F) {
	ctx := context.Background()
	tc := []string{
		"id=*;type=*;actions=read,list;output_fields=",
		`{"id": "*", "type": "*", "actions": ["read", "list"], "output_fields": []}`,
		"id=*;type=*;actions=read,list",
		"ids=*;type=*;actions=read,list",
		`{"type":"host-catalog","actions":["create"]}`,
		`{"id":"u_foobar","actions":["read"]}`,
		`{"id":"u_foobar","actions":["read"],"output_fields":["version","id","name"]}`,
		`{"id":"u_foobar","output_fields":["version","id","name"]}`,
		`type=host-catalog;actions=create`,
		`ids=hcst_foobar,hcst_foobaz;actions=read;output_fields=version,ids,name`,
		`id=hcst_foobar;actions=read`,
		`id=acctpw_foobar;actions=read`,
		`id={{    user.id}};actions=read,update`,
		"type=host-catalog;actions=create",
		"type=*;actions=*",
		"id=*;type=*;actions=*",
		"ids=*;type=*;actions=*",
		"id=*;type=*;actions=read,list",
		"ids=*;type=*;actions=read,list",
		"id=foobar;actions=read;output_fields=version,id,name",
		"ids=foobar,foobaz;actions=read;output_fields=version,id,name",
		"id={{account.id}};actions=update,read",
		"ids={{account.id}},{{user.id}};actions=update,read",
		`{"id":"foobar","type":"host-catalog","actions":["create"]}`,
		`{"ids":["foobar"],"type":"host-catalog","actions":["create"]}`,
		`{"ids":["\""]}`,
	}
	for _, tc := range tc {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, grant string) {
		g, err := Parse(ctx, GrantTuple{GrantScopeId: "global", Grant: grant}, WithSkipFinalValidation(true))
		if err != nil {
			return
		}
		g2, err := Parse(ctx, GrantTuple{GrantScopeId: "global", Grant: g.CanonicalString()}, WithSkipFinalValidation(true))
		if err != nil {
			t.Fatal("Failed to parse canonical string:", err)
		}
		if g.CanonicalString() != g2.CanonicalString() {
			t.Errorf("grant roundtrip failed, input %q, output %q", g.CanonicalString(), g2.CanonicalString())
		}
		jsonBytes, err := g.MarshalJSON()
		if err != nil {
			t.Error("Failed to marshal JSON:", err)
		}
		g3, err := Parse(ctx, GrantTuple{GrantScopeId: "global", Grant: string(jsonBytes)}, WithSkipFinalValidation(true))
		if err != nil {
			t.Fatal("Failed to parse json string:", err)
		}
		if g.CanonicalString() != g3.CanonicalString() {
			t.Errorf("grant JSON roundtrip failed, input %q, output %q", g.CanonicalString(), g3.CanonicalString())
		}
	})
}
