// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"testing"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	withKms := new(kms.Kms)
	res := new(perms.Resource)

	// test default values
	defaultOpts := getDefaultOptions()
	assert.Equal(t, options{}, defaultOpts)

	opts := getOpts(
		WithScopeId("foo"),
		WithPin("bar"),
		WithId("zip"),
		WithAction(action.AddHosts),
		WithUserId("user"),
		WithKms(withKms),
		WithRecoveryTokenNotAllowed(true),
		WithAnonymousUserNotAllowed(true),
		WithRecursive(true),
		WithResource(res),
		WithActions([]string{"callback"}),
	)
	exp := options{
		withScopeId:                 "foo",
		withPin:                     "bar",
		withId:                      "zip",
		withAction:                  action.AddHosts,
		withUserId:                  "user",
		withKms:                     withKms,
		withRecoveryTokenNotAllowed: true,
		withAnonymousUserNotAllowed: true,
		withRecursive:               true,
		withResource:                res,
		withActions:                 []string{"callback"},
	}
	assert.Equal(t, exp, opts)
}
