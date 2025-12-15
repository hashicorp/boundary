// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// AuthMethodListQueryResult describes the result from the
// auth method list query used to list all auth method subtypes.
type AuthMethodListQueryResult struct {
	// PublicId is a surrogate key suitable for use in a public API.
	PublicId string `gorm:"primary_key"`
	// The Scope Id of the scope this auth method belongs to, must be set.
	ScopeId string
	// Sets the primary subtype of the auth method.
	IsPrimaryAuthMethod bool
	// Optional name of the auth method.
	Name string
	// Optional description of the auth method.
	Description string
	// Create time of the auth method.
	CreateTime *timestamp.Timestamp
	// Update time of the auth method.
	UpdateTime *timestamp.Timestamp
	// Version of the auth method.
	Version uint32
	// Optionally set by ldap or oidc auth methods.
	State string
	Certs string
	// Optionally set by ldap auth method.
	StartTLS                 bool
	InsecureTLS              bool
	DiscoverDn               bool
	AnonGroupSearch          bool
	UpnDomain                string
	Urls                     string
	UserDn                   string
	UserAttr                 string
	UserFilter               string
	EnableGroups             bool
	UseTokenGroups           bool
	GroupDn                  string
	GroupAttr                string
	GroupFilter              string
	ClientCertificateKeyHmac []byte
	ClientCertificateKeyId   string
	ClientCertificateCert    []byte
	BindDn                   string
	BindKeyId                string
	AccountAttributeMap      string
	DereferenceAliases       string
	MaximumPageSize          uint32
	// Optionally set by oidc auth method.
	DisableDiscoveredConfigValidation bool
	Issuer                            string
	ClientId                          string
	ClientSecretHmac                  string
	KeyId                             string
	MaxAge                            int
	Algs                              string
	ApiUrl                            string
	Auds                              string
	ClaimsScopes                      string
	AccountClaimMaps                  string
	Prompts                           string
	// Optionally set by password auth method.
	PasswordConfId     string
	MinLoginNameLength uint32
	MinPasswordLength  uint32
	// The subtype of the auth method.
	Subtype string
}

func (am *AuthMethodListQueryResult) toAuthMethod(ctx context.Context) (AuthMethod, error) {
	const op = "auth.(*AuthMethodListQueryResult).toAuthMethod"

	newFn, ok := subtypeRegistry.newFunc(globals.Subtype(am.Subtype))
	if !ok {
		return nil, errors.New(ctx,
			errors.InvalidParameter,
			op,
			fmt.Sprintf("%s is an unknown auth method subtype of %s", am.PublicId, am.Subtype),
		)
	}

	return newFn(ctx, am)
}
