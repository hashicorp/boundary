package template

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: Although this does a basic test of template generation, other tests
// that are closer to where this library is used can and should also be enhanced
// over time. For instance, TestAuthorizeSession from target_service_test.go has
// been enhanced to use this library to check output against Vault.

func TestErrors(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	// No template
	parsed, err := New(ctx, "")
	assert.Error(err)
	assert.Nil(parsed)

	// Bad template
	parsed, err = New(ctx, "{{ foobar")
	assert.Error(err)
	assert.Nil(parsed)

	// Good template
	ts := "Foobar:{{ .User.Name }}"
	parsed, err = New(ctx, ts)
	assert.NoError(err)
	require.NotNil(parsed)
	assert.Equal(ts, parsed.raw)
	assert.NotNil(parsed.tmpl)
	assert.Len(parsed.funcMap, 1)

	// Test out errors on the parsed value

	// Nil template
	oldTmpl := parsed.tmpl
	parsed.tmpl = nil
	out, err := parsed.Generate(ctx, Data{})
	assert.Error(err)
	assert.Empty(out)
	parsed.tmpl = oldTmpl

	// Nil
	out, err = parsed.Generate(ctx, nil)
	assert.Error(err)
	assert.Empty(out)

	// Nil pointer
	var nilData *Data
	out, err = parsed.Generate(ctx, nilData)
	assert.Error(err)
	assert.Empty(out)

	// Good
	out, err = parsed.Generate(ctx, Data{})
	assert.NoError(err)
	assert.Equal(out, "Foobar:")
}

func TestGenerate(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	data := Data{
		User: User{
			Id:       "userId",
			Name:     "userName",
			FullName: "userFullName",
			Email:    "user@email.com",
		},
		Account: Account{
			Id:        "accountId",
			Name:      "accountName",
			LoginName: "accountLoginName",
			Subject:   "accountSubject",
			Email:     "account@email.com",
		},
	}
	raw := strings.TrimSpace(`
{{ .User.Id }}
{{ .User.Name }}
{{ .User.FullName }}
{{ .User.Email }}
{{ truncateFrom .User.Email "@" }}
{{ .Account.Id }}
{{ .Account.Name }}
{{ .Account.LoginName }}
{{ .Account.Subject }}
{{ .Account.Email }}
{{ truncateFrom .Account.Email "@" }}
`)

	parsed, err := New(ctx, raw)
	require.NoError(err)
	require.NotNil(parsed)

	// Empty should result in empty result
	out, err := parsed.Generate(ctx, Data{})
	require.NoError(err)
	assert.Empty(strings.TrimSpace(out))

	// Do again with non-empty data
	out, err = parsed.Generate(ctx, data)
	require.NoError(err)

	exp := strings.TrimSpace(`
userId
userName
userFullName
user@email.com
user
accountId
accountName
accountLoginName
accountSubject
account@email.com
account
`)

	assert.Equal(exp, out)
}
