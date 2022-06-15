package perms

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/intglobals"
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
			name: "empty action with output fields",
			input: Grant{
				OutputFields: OutputFieldsMap{
					"id": true,
				},
			},
			result: Grant{
				OutputFields: OutputFieldsMap{
					"id": true,
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
	var g Grant
	for i := resource.Unknown; i <= resource.Credential; i++ {
		g.typ = i
		if i == resource.Controller {
			assert.Error(t, g.validateType())
		} else {
			assert.NoError(t, g.validateType())
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
			name: "output fields",
			input: Grant{
				id: "baz",
				scope: Scope{
					Type: scope.Project,
				},
				typ: resource.Group,
				OutputFields: OutputFieldsMap{
					"name":    true,
					"version": true,
					"id":      true,
				},
			},
			jsonOutput:      `{"id":"baz","output_fields":["id","name","version"],"type":"group"}`,
			canonicalString: `id=baz;type=group;output_fields=id,name,version`,
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
				OutputFields: OutputFieldsMap{
					"name":    true,
					"version": true,
					"id":      true,
				},
			},
			jsonOutput:      `{"actions":["create","read"],"id":"baz","output_fields":["id","name","version"],"type":"group"}`,
			canonicalString: `id=baz;type=group;actions=create,read;output_fields=id,name,version`,
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
			name: "good output fields",
			expected: Grant{
				OutputFields: OutputFieldsMap{
					"name":    true,
					"version": true,
					"id":      true,
				},
			},
			jsonInput: `{"output_fields":["id","name","version"]}`,
			textInput: `output_fields=id,version,name`,
		},
		{
			name:      "bad output fields",
			jsonInput: `{"output_fields":true}`,
			jsonErr:   `perms.(Grant).unmarshalJSON: unable to interpret "output_fields" as array: parameter violation: error #100`,
			textInput: `output_fields=id=version,name`,
			textErr:   `perms.(Grant).unmarshalText: segment "output_fields=id=version,name" not formatted correctly, wrong number of equal signs: parameter violation: error #100`,
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
			name:  "bad create action for id",
			input: "id=foobar;actions=create",
			err:   `perms.Parse: parsed grant string contains create or list action in a format that does not allow these: parameter violation: error #100`,
		},
		{
			name:  "bad create action for id with other perms",
			input: "id=foobar;actions=read,create",
			err:   `perms.Parse: parsed grant string contains create or list action in a format that does not allow these: parameter violation: error #100`,
		},
		{
			name:  "bad list action for id",
			input: "id=foobar;actions=list",
			err:   `perms.Parse: parsed grant string contains create or list action in a format that does not allow these: parameter violation: error #100`,
		},
		{
			name:  "bad list action for id with other perms",
			input: "type=host-catalog;actions=list,read",
			err:   `perms.Parse: parsed grant string contains non-create or non-list action in a format that only allows these: parameter violation: error #100`,
		},
		{
			name:  "wildcard id and actions without collection",
			input: "id=*;actions=read",
			err:   `perms.Parse: parsed grant string would not result in any action being authorized: parameter violation: error #100`,
		},
		{
			name:  "wildcard id and actions with list",
			input: "id=*;actions=read,list",
			err:   `perms.Parse: parsed grant string contains create or list action in a format that does not allow these: parameter violation: error #100`,
		},
		{
			name:  "wildcard type with no id",
			input: "type=*;actions=read,list",
			err:   `perms.Parse: parsed grant string contains wildcard type with no id value: parameter violation: error #100`,
		},
		{
			name:  "empty id and type",
			input: "actions=create",
			err:   `perms.Parse: parsed grant string contains no id or type: parameter violation: error #100`,
		},
		{
			name:  "empty output fields",
			input: "id=*;type=*;actions=read,list;output_fields=",
			err:   `perms.Parse: unable to parse grant string: perms.(Grant).unmarshalText: segment "output_fields=" not formatted correctly, missing value: parameter violation: error #100`,
		},
		{
			name:  "empty output fields json",
			input: `{"id": "*", "type": "*", "actions": ["read", "list"], "output_fields": []}`,
			err:   "perms.Parse: parsed grant string has output_fields set but empty: parameter violation: error #100",
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
			name:  "good json output fields",
			input: `{"id":"foobar","actions":["read"],"output_fields":["version","id","name"]}`,
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
				OutputFields: OutputFieldsMap{
					"version": true,
					"id":      true,
					"name":    true,
				},
			},
		},
		{
			name:  "good json output fields no action",
			input: `{"id":"foobar","output_fields":["version","id","name"]}`,
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id:  "foobar",
				typ: resource.Unknown,
				OutputFields: OutputFieldsMap{
					"version": true,
					"id":      true,
					"name":    true,
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
			name:  "good output fields",
			input: `id=foobar;actions=read;output_fields=version,id,name`,
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
				OutputFields: OutputFieldsMap{
					"version": true,
					"id":      true,
					"name":    true,
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
			accountId: fmt.Sprintf("%s_1234567890", intglobals.OldPasswordAccountPrefix),
			err:       `perms.Parse: unknown template "{{superman}}" in grant "id" value: parameter violation: error #100`,
		},
		{
			name:      "bad new account id template",
			input:     `id={{superman}};actions=read`,
			accountId: fmt.Sprintf("%s_1234567890", intglobals.NewPasswordAccountPrefix),
			err:       `perms.Parse: unknown template "{{superman}}" in grant "id" value: parameter violation: error #100`,
		},
		{
			name:      "good old account id template",
			input:     `id={{    account.id}};actions=update,read`,
			accountId: fmt.Sprintf("%s_1234567890", intglobals.OldPasswordAccountPrefix),
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id: fmt.Sprintf("%s_1234567890", intglobals.OldPasswordAccountPrefix),
				actions: map[action.Type]bool{
					action.Update: true,
					action.Read:   true,
				},
			},
		},
		{
			name:      "good new account id template",
			input:     `id={{    account.id}};actions=update,read`,
			accountId: fmt.Sprintf("%s_1234567890", intglobals.NewPasswordAccountPrefix),
			expected: Grant{
				scope: Scope{
					Id:   "o_scope",
					Type: scope.Org,
				},
				id: fmt.Sprintf("%s_1234567890", intglobals.NewPasswordAccountPrefix),
				actions: map[action.Type]bool{
					action.Update: true,
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
