package perms

import (
	"testing"

	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
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
				actionsBeingParsed: []string{"list", "create", "update", "list:self", "read", "delete", "authenticate", "authorize-session"},
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
					action.ListSelf:         true,
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
			name: "everything",
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
			},
			jsonOutput:      `{"actions":["create","read"],"id":"baz","type":"group"}`,
			canonicalString: `id=baz;type=group;actions=create,read`,
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
			jsonErr:   "perms.(Grant).unmarshalJSON: error occurred during decode, encoding issue: error #303: invalid character 'w' looking for beginning of value",
		},
		{
			name:      "bad segment",
			jsonInput: `{"id":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "id" as string: parameter violation: error #100`,
			textInput: `id=`,
			textErr:   `perms.(Grant).unmarshalText: segment "id=" not formatted correctly, missing value: parameter violation: error #100`,
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
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "id" as string: parameter violation: error #100`,
			textInput: `=id`,
			textErr:   `perms.(Grant).unmarshalText: segment "=id" not formatted correctly, missing key: parameter violation: error #100`,
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
			input: "id=foobar;type=barfoo;actions=create,read",
			err:   `perms.Parse: unable to parse grant string: perms.(Grant).unmarshalText: unknown type specifier "barfoo": parameter violation: error #100`,
		},
		{
			name:  "bad actions",
			input: "id=foobar;type=host-catalog;actions=createread",
			err:   `perms.Parse: perms.(Grant).parseAndValidateActions: unknown action "createread": parameter violation: error #100`,
		},
		{
			name:  "empty id and type",
			input: "actions=create",
			err:   `perms.Parse: parsed grant string would not result in any action being authorized: parameter violation: error #100`,
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
			input: `{"id":"foobar","actions":["read"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
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
			input: `id=foobar;actions=read`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:          "default project scope",
			input:         `id=foobar;actions=read`,
			scopeOverride: "p_1234",
			expected: Grant{
				scope: Scope{
					Id:   "p_1234",
					Type: scope.Project,
				},
				id:  "foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:          "default org scope",
			input:         `id=foobar;actions=read`,
			scopeOverride: "o_1234",
			expected: Grant{
				scope: Scope{
					Id:   "o_1234",
					Type: scope.Org,
				},
				id:  "foobar",
				typ: resource.Unknown,
				actions: map[action.Type]bool{
					action.Read: true,
				},
			},
		},
		{
			name:          "default global scope",
			input:         `id=foobar;actions=read`,
			scopeOverride: "global",
			expected: Grant{
				scope: Scope{
					Id:   "global",
					Type: scope.Global,
				},
				id:  "foobar",
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
			name:   "good user id template",
			input:  `id={{    user.id}};actions=create,read`,
			userId: "u_abcd1234",
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id: "u_abcd1234",
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
			},
		},
		{
			name:      "bad account id template",
			input:     `id={{superman}};actions=create,read`,
			accountId: "apw_1234567890",
			err:       `perms.Parse: unknown template "{{superman}}" in grant "id" value: parameter violation: error #100`,
		},
		{
			name:      "good account id template",
			input:     `id={{    account.id}};actions=create,read`,
			accountId: "apw_1234567890",
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id: "apw_1234567890",
				actions: map[action.Type]bool{
					action.Create: true,
					action.Read:   true,
				},
			},
		},
	}

	_, err := Parse("", "")
	require.Error(t, err)
	assert.Equal(t, "perms.Parse: missing grant string: parameter violation: error #100", err.Error())

	_, err = Parse("", "{}")
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
			grant, err := Parse(scope, test.input, WithUserId(test.userId), WithAccountId(test.accountId))
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
