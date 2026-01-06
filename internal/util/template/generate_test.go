// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package template

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/util"
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
	assert.Len(parsed.funcMap, 2)

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

	// Nil internal data
	_, err = parsed.Generate(ctx, Data{})
	assert.Error(err)

	// Good data
	out, err = parsed.Generate(ctx, Data{User: User{Name: util.Pointer("name")}})
	require.NoError(err)
	assert.Equal("Foobar:name", out)
}

func TestGenerate(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	data := Data{
		User: User{
			Id:       util.Pointer("userId"),
			Name:     util.Pointer("userName"),
			FullName: util.Pointer("userFullName"),
			Email:    util.Pointer("user@email.com"),
		},
		Account: Account{
			Id:        util.Pointer("accountId"),
			Name:      util.Pointer("accountName"),
			LoginName: util.Pointer("accountLoginName"),
			Subject:   util.Pointer("accountSubject"),
			Email:     util.Pointer("account@email.com"),
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
{{ coalesce "" .Account.LoginName .Account.Name }}
{{ coalesce "" "" .Account.Name .Account.LoginName }}
`)

	parsed, err := New(ctx, raw)
	require.NoError(err)
	require.NotNil(parsed)

	// Ensure we error with required data
	_, err = parsed.Generate(ctx, Data{})
	require.Error(err)

	// Do again with non-empty data
	out, err := parsed.Generate(ctx, data)
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
accountLoginName
accountName
`)

	assert.Equal(exp, out)
}
