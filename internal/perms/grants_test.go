package perms

import (
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/iam"
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
				actions: map[iam.Action]bool{
					iam.ActionAll: true,
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
				actions: map[iam.Action]bool{
					iam.ActionList:    true,
					iam.ActionCreate:  true,
					iam.ActionUpdate:  true,
					iam.ActionRead:    true,
					iam.ActionDelete:  true,
					iam.ActionAuthen:  true,
					iam.ActionConnect: true,
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
				typ: "foobar",
			},
			errResult: `unknown type specifier "foobar"`,
		},
		{
			name: "valid specifier",
			input: Grant{
				typ: TypeHostCatalog,
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

func Test_ValidateProject(t *testing.T) {
	t.Parallel()

	type input struct {
		name      string
		input     Grant
		output    Grant
		errResult string
	}

	tests := []input{
		{
			name: "no project",
			input: Grant{
				scope: Scope{
					Type: iam.OrganizationScope,
				},
			},
			output: Grant{
				scope: Scope{
					Type: iam.OrganizationScope,
				},
			},
		},
		{
			name: "project, organization scope",
			input: Grant{
				project: "foobar",
				scope: Scope{
					Type: iam.OrganizationScope,
				},
			},
			output: Grant{
				project: "foobar",
				scope: Scope{
					Type: iam.ProjectScope,
					Id:   "foobar",
				},
			},
		},
		{
			name: "project, non-organization scope",
			input: Grant{
				project: "foobar",
				scope: Scope{
					Type: iam.ProjectScope,
				},
			},
			errResult: "cannot specify a project in the grant when the scope is not an organization",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.input.validateAndModifyProject()
			if test.errResult == "" {
				require.NoError(t, err)
				assert.Equal(t, test.output, test.input)
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
					Type: iam.OrganizationScope,
				},
			},
			jsonOutput:      `{}`,
			canonicalString: ``,
		},
		{
			name: "project",
			input: Grant{
				project: "foobar",
				scope: Scope{
					Type: iam.OrganizationScope,
				},
			},
			jsonOutput:      `{"project":"foobar"}`,
			canonicalString: `project=foobar`,
		},
		{
			name: "project and type",
			input: Grant{
				project: "foobar",
				scope: Scope{
					Type: iam.ProjectScope,
				},
				typ: TypeGroup,
			},
			jsonOutput:      `{"project":"foobar","type":"group"}`,
			canonicalString: `project=foobar;type=group`,
		},
		{
			name: "project, type, and id",
			input: Grant{
				id:      "baz",
				project: "foobar",
				scope: Scope{
					Type: iam.ProjectScope,
				},
				typ: TypeGroup,
			},
			jsonOutput:      `{"id":"baz","project":"foobar","type":"group"}`,
			canonicalString: `project=foobar;id=baz;type=group`,
		},
		{
			name: "everything",
			input: Grant{
				id:      "baz",
				project: "foobar",
				scope: Scope{
					Type: iam.ProjectScope,
				},
				typ: TypeGroup,
				actions: map[iam.Action]bool{
					iam.ActionCreate: true,
					iam.ActionRead:   true,
				},
				actionsBeingParsed: []string{"create", "read"},
			},
			jsonOutput:      `{"actions":["create","read"],"id":"baz","project":"foobar","type":"group"}`,
			canonicalString: `project=foobar;id=baz;type=group;actions=create,read`,
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
			name: "good project",
			expected: Grant{
				project: "foobar",
			},
			jsonInput: `{"project":"foobar"}`,
			textInput: `project=foobar`,
		},
		{
			name:      "bad project",
			jsonInput: `{"project":true}`,
			jsonErr:   `unable to interpret "project" as string`,
			textInput: `project=`,
			textErr:   `segment "project=" not formatted correctly, missing value`,
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
				typ: "host-catalog",
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

	assert := assert.New(t)
	require := require.New(t)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			name:  "good json",
			input: `{"project":"proj","id":"foobar","type":"host-catalog","actions":["create","read"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "proj",
					Type: iam.ProjectScope,
				},
				project: "proj",
				id:      "foobar",
				typ:     "host-catalog",
				actions: map[iam.Action]bool{
					iam.ActionCreate: true,
					iam.ActionRead:   true,
				},
			},
		},
		{
			name:  "good text",
			input: `project=proj;id=foobar;type=host-catalog;actions=create,read`,
			expected: Grant{
				scope: Scope{
					Id:   "proj",
					Type: iam.ProjectScope,
				},
				project: "proj",
				id:      "foobar",
				typ:     "host-catalog",
				actions: map[iam.Action]bool{
					iam.ActionCreate: true,
					iam.ActionRead:   true,
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
					Type: iam.OrganizationScope,
				},
				id: "u_abcd1234",
				actions: map[iam.Action]bool{
					iam.ActionCreate: true,
					iam.ActionRead:   true,
				},
			},
		},
	}

	assert := assert.New(t)
	require := require.New(t)

	_, err := Parse(Scope{}, "", "")
	require.Error(err)
	assert.Equal("grant string is empty", err.Error())

	_, err = Parse(Scope{}, "", "{}")
	require.Error(err)
	assert.Equal("invalid scope type", err.Error())

	_, err = Parse(Scope{Type: iam.OrganizationScope}, "", "{}")
	require.Error(err)
	assert.Equal("no scope ID provided", err.Error())

	_, err = Parse(Scope{Id: "foobar", Type: iam.ProjectScope}, "", `project=foobar`)
	require.Error(err)
	assert.Equal("cannot specify a project in the grant when the scope is not an organization", err.Error())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant, err := Parse(Scope{Id: "scope", Type: iam.OrganizationScope}, test.userId, test.input)
			if test.err != "" {
				require.Error(err)
				assert.True(strings.HasPrefix(err.Error(), test.err))
			} else {
				require.NoError(err)
				assert.Equal(test.expected, grant)
			}
		})
	}
}
