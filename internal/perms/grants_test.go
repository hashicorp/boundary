package perms

import (
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ActionParsingValidation(t *testing.T) {
	t.Parallel()

	type input struct {
		name      string
		input     Grant
		errResult string
		result    Grant
	}

	tests := []input{
		{
			name:      "no actions",
			errResult: "no actions specified",
		},
		{
			name: "empty action",
			input: Grant{
				actionsBeingParsed: []string{"create", "", "read"},
			},
			errResult: "empty action found",
		},
		{
			name: "unknown action",
			input: Grant{
				actionsBeingParsed: []string{"create", "foobar", "read"},
			},
			errResult: `unknown action "foobar"`,
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
				actionsBeingParsed: []string{"list", "create", "update", "*", "read", "delete", "authen", "connect"},
			},
			errResult: `"*" cannot be specified with other actions`,
		},
		{
			name: "all valid",
			input: Grant{
				actionsBeingParsed: []string{"list", "create", "update", "read", "delete", "authen", "connect"},
			},
			result: Grant{
				actions: map[action.Type]bool{
					action.List:         true,
					action.Create:       true,
					action.Update:       true,
					action.Read:         true,
					action.Delete:       true,
					action.Authenticate: true,
					action.Connect:      true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.input.parseAndValidateActions()
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

	type input struct {
		name      string
		input     Grant
		errResult string
	}

	tests := []input{
		{
			name: "no specifier",
		},
		{
			name: "unknown specifier",
			input: Grant{
				typ: resource.RoleGrant,
			},
			errResult: `unknown type specifier "role-grant"`,
		},
		{
			name: "valid specifier",
			input: Grant{
				typ: resource.HostCatalog,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.input.validateType()
			if test.errResult == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, test.errResult, err.Error())
			}
		})
	}
}

func Test_MarshallingAndCloning(t *testing.T) {
	t.Parallel()

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
					Type: scope.Organization,
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
				typ: resource.StaticGroup,
			},
			jsonOutput:      `{"id":"baz","type":"static-group"}`,
			canonicalString: `id=baz;type=static-group`,
		},
		{
			name: "everything",
			input: Grant{
				id: "baz",
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.StaticGroup,
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
				actionsBeingParsed: []string{"create", "read"},
			},
			jsonOutput:      `{"actions":["create","read"],"id":"baz","type":"static-group"}`,
			canonicalString: `id=baz;type=static-group;actions=create,read`,
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
			jsonErr:   "invalid character 'w' looking for beginning of value",
		},
		{
			name:      "bad segment",
			jsonInput: `{"id":true}`,
			jsonErr:   `unable to interpret "id" as string`,
			textInput: `id=`,
			textErr:   `segment "id=" not formatted correctly, missing value`,
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
			name:      "bad id",
			jsonInput: `{"id":true}`,
			jsonErr:   `unable to interpret "id" as string`,
			textInput: `=id`,
			textErr:   `segment "=id" not formatted correctly, missing key`,
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
			jsonErr:   `unable to interpret "type" as string`,
			textInput: `type=host-catalog=id`,
			textErr:   `segment "type=host-catalog=id" not formatted correctly, wrong number of equal signs`,
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
			jsonErr:   `unable to interpret "actions" as array`,
			textInput: `type=host-catalog=id`,
			textErr:   `segment "type=host-catalog=id" not formatted correctly, wrong number of equal signs`,
		},
		{
			name:      "empty actions",
			jsonInput: `{"actions":[""]}`,
			jsonErr:   `empty action found`,
			textInput: `actions=,`,
			textErr:   `empty action found`,
		},
		{
			name:      "bad json action",
			jsonInput: `{"actions":[1, true]}`,
			jsonErr:   `unable to interpret 1 in actions array as string`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			var g Grant
			if test.jsonInput != "" {
				err := g.unmarshalJSON([]byte(test.jsonInput))
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
				err := g.unmarshalText(test.textInput)
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

	type input struct {
		name     string
		input    string
		userId   string
		err      string
		expected Grant
	}

	tests := []input{
		{
			name: "empty",
			err:  `grant string is empty`,
		},
		{
			name:  "bad json",
			input: "{2:193}",
			err:   `unable to parse JSON grant string:`,
		},
		{
			name:  "bad text",
			input: "id=foo=bar",
			err:   `unable to parse grant string:`,
		},
		{
			name:  "bad type",
			input: "id=foobar;type=barfoo;actions=create,read",
			err:   `unknown type specifier "barfoo"`,
		},
		{
			name:  "bad actions",
			input: "id=foobar;type=host-catalog;actions=createread",
			err:   `unknown action "createread"`,
		},
		{
			name:  "empty id and type",
			input: "actions=create",
			err:   `"id" and "type" cannot both be empty`,
		},
		{
			name:  "good json",
			input: `{"id":"foobar","type":"host-catalog","actions":["create","read"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "scope",
					Type: scope.Organization,
				},
				id:  "foobar",
				typ: resource.HostCatalog,
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
			},
		},
		{
			name:  "good text",
			input: `id=foobar;type=host-catalog;actions=create,read`,
			expected: Grant{
				scope: Scope{
					Id:   "scope",
					Type: scope.Organization,
				},
				id:  "foobar",
				typ: resource.HostCatalog,
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
			},
		},
		{
			name:   "bad user id template",
			input:  `id={{superman}};actions=create,read`,
			userId: "u_abcd1234",
			err:    `unknown template "{{superman}}" in grant "id" value`,
		},
		{
			name:   "good user id template",
			input:  `id={{    user.id}};actions=create,read`,
			userId: "u_abcd1234",
			expected: Grant{
				scope: Scope{
					Id:   "scope",
					Type: scope.Organization,
				},
				id: "u_abcd1234",
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
			},
		},
	}

	_, err := Parse(Scope{}, "", "")
	require.Error(t, err)
	assert.Equal(t, "grant string is empty", err.Error())

	_, err = Parse(Scope{}, "", "{}")
	require.Error(t, err)
	assert.Equal(t, "invalid scope type", err.Error())

	_, err = Parse(Scope{Type: scope.Organization}, "", "{}")
	require.Error(t, err)
	assert.Equal(t, "no scope ID provided", err.Error())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			grant, err := Parse(Scope{Id: "scope", Type: scope.Organization}, test.userId, test.input)
			if test.err != "" {
				require.Error(err)
				assert.True(strings.Contains(err.Error(), test.err))
			} else {
				require.NoError(err)
				assert.Equal(test.expected, grant)
			}
		})
	}
}
