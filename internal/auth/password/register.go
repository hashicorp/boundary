// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth"
)

func init() {
	auth.RegisterAuthMethodSubtype("password", &authMethodHooks{})
}

type authMethodHooks struct{}

// NewAuthMethod creates a new static auth method from the result
func (authMethodHooks) NewAuthMethod(ctx context.Context, result *auth.AuthMethodListQueryResult) (auth.AuthMethod, error) {
	am := allocAuthMethod()
	am.PublicId = result.PublicId
	am.ScopeId = result.ScopeId
	am.IsPrimaryAuthMethod = result.IsPrimaryAuthMethod
	am.CreateTime = result.CreateTime
	am.UpdateTime = result.UpdateTime
	am.Name = result.Name
	am.Description = result.Description
	am.Version = result.Version
	am.PasswordConfId = result.PasswordConfId
	am.MinLoginNameLength = result.MinLoginNameLength
	am.MinPasswordLength = result.MinPasswordLength

	return &am, nil
}
