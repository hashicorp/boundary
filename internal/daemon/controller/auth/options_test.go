// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"testing"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	withKms := new(kms.Kms)
	res := new(perms.Resource)

	opts := getOpts(
		WithScopeId("foo"),
		WithPin("bar"),
		WithId("zip"),
		WithAction(action.AddHosts),
		WithType(resource.Group),
		WithUserId("user"),
		WithKms(withKms),
		WithRecoveryTokenNotAllowed(true),
		WithAnonymousUserNotAllowed(true),
		WithResource(res),
	)
	exp := options{
		withScopeId:                 "foo",
		withPin:                     "bar",
		withId:                      "zip",
		withAction:                  action.AddHosts,
		withType:                    resource.Group,
		withUserId:                  "user",
		withKms:                     withKms,
		withRecoveryTokenNotAllowed: true,
		withAnonymousUserNotAllowed: true,
		withResource:                res,
	}
	assert.Equal(t, exp, opts)
}
