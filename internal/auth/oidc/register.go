// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
)

func init() {
	auth.RegisterAuthMethodSubtype("oidc", &authMethodHooks{})
}

type authMethodHooks struct{}

// NewAuthMethod creates a new oidc auth method from the result
func (authMethodHooks) NewAuthMethod(ctx context.Context, result *auth.AuthMethodListQueryResult) (auth.AuthMethod, error) {
	delimiter := "|"

	am := AllocAuthMethod()
	am.PublicId = result.PublicId
	am.ScopeId = result.ScopeId
	am.IsPrimaryAuthMethod = result.IsPrimaryAuthMethod
	am.Name = result.Name
	am.Description = result.Description
	am.CreateTime = result.CreateTime
	am.UpdateTime = result.UpdateTime
	am.Version = result.Version
	am.OperationalState = result.State
	am.DisableDiscoveredConfigValidation = result.DisableDiscoveredConfigValidation
	am.Issuer = result.Issuer
	am.ClientId = result.ClientId
	am.ClientSecretHmac = result.ClientSecretHmac
	am.KeyId = result.KeyId
	am.MaxAge = int32(result.MaxAge)
	am.ApiUrl = result.ApiUrl
	if result.Algs != "" {
		am.SigningAlgs = strings.Split(result.Algs, delimiter)
	}
	if result.Auds != "" {
		am.AudClaims = strings.Split(result.Auds, delimiter)
	}
	if result.Certs != "" {
		am.Certificates = strings.Split(result.Certs, delimiter)
	}
	if result.ClaimsScopes != "" {
		am.ClaimsScopes = strings.Split(result.ClaimsScopes, delimiter)
	}
	if result.AccountClaimMaps != "" {
		am.AccountClaimMaps = strings.Split(result.AccountClaimMaps, delimiter)
	}
	if result.Prompts != "" {
		am.Prompts = strings.Split(result.Prompts, delimiter)
	}

	return &am, nil
}
