// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
)

func init() {
	auth.RegisterAuthMethodSubtype("ldap", &authMethodHooks{})
}

type authMethodHooks struct{}

// NewAuthMethod creates a new static auth method from the result
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
	am.StartTls = result.StartTLS
	am.InsecureTls = result.InsecureTLS
	am.DiscoverDn = result.DiscoverDn
	am.AnonGroupSearch = result.AnonGroupSearch
	am.EnableGroups = result.EnableGroups
	am.UseTokenGroups = result.UseTokenGroups
	am.UpnDomain = result.UpnDomain
	if result.Urls != "" {
		am.Urls = strings.Split(result.Urls, delimiter)
	}
	if result.Certs != "" {
		am.Certificates = strings.Split(result.Certs, delimiter)
	}
	am.UserDn = result.UserDn
	am.UserAttr = result.UserAttr
	am.UserFilter = result.UserFilter
	am.GroupDn = result.GroupDn
	am.GroupAttr = result.GroupAttr
	am.GroupFilter = result.GroupFilter
	am.ClientCertificateKeyHmac = result.ClientCertificateKeyHmac
	am.ClientCertificate = string(result.ClientCertificateCert)
	am.BindDn = result.BindDn
	if result.AccountAttributeMap != "" {
		am.AccountAttributeMaps = strings.Split(result.AccountAttributeMap, delimiter)
	}
	am.DereferenceAliases = result.DereferenceAliases
	am.MaximumPageSize = result.MaximumPageSize

	return &am, nil
}
