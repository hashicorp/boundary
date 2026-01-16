// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/cap/ldap"
)

const (
	DefaultEmailAttribute    = "email"
	DefaultFullNameAttribute = "fullName"
	DefaultRequestTimeout    = 5 // seconds
)

// Authenticate authenticates loginName and password via the auth method's
// configured LDAP service. The account for the loginName is returned if
// authentication is successful. Returns nil if authentication fails.
//
// If the AuthMethod.EnableGroups is true, then the authenticated user's groups
// will be returned in account.
//
// Authenticate will update the stored values for the authenticated user's
// Account: FullName, Email, Dn, EntryAttributes, and MemberOfGroups.
//
// Note: the auth_method table uses public id as its PK, so there's no need a
// scope id parameter.
func (r *Repository) Authenticate(ctx context.Context, authMethodId, loginName, password string) (*Account, error) {
	const op = "ldap.(Repository).Authenticate"
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id", errors.WithoutEvent())
	case loginName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing login name", errors.WithoutEvent())
	case password == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password", errors.WithoutEvent())
	}

	// lookup auth method
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup auth method id: %q", authMethodId))
	}
	if am == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("auth method id %q not found", authMethodId))
	}

	var clientTLSKeyPem string
	if am.ClientCertificateKey != nil {
		clientTLSKeyPem = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: am.ClientCertificateKey}))
	}

	// config cap ldap provider
	client, err := ldap.NewClient(ctx, &ldap.ClientConfig{
		IncludeUserAttributes: true,
		StartTLS:              am.StartTls,
		InsecureTLS:           am.InsecureTls,
		DiscoverDN:            am.DiscoverDn,
		AnonymousGroupSearch:  am.AnonGroupSearch,
		UPNDomain:             am.UpnDomain,
		URLs:                  am.Urls,
		UserDN:                am.UserDn,
		UserFilter:            am.UserFilter,
		UserAttr:              am.UserAttr,
		IncludeUserGroups:     am.EnableGroups,
		UseTokenGroups:        am.UseTokenGroups,
		GroupDN:               am.GroupDn,
		GroupAttr:             am.GroupAttr,
		GroupFilter:           am.GroupFilter,
		Certificates:          am.Certificates,
		ClientTLSKey:          clientTLSKeyPem,
		ClientTLSCert:         am.ClientCertificate,
		BindDN:                am.BindDn,
		BindPassword:          am.BindPassword,
		RequestTimeout:        DefaultRequestTimeout,
		DerefAliases:          am.DereferenceAliases,
		MaximumPageSize:       int(am.MaximumPageSize),
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to initialize ldap client with auth method retrieved from database"))
	}
	defer client.Close(ctx)

	// authen user
	authResult, err := client.Authenticate(ctx, loginName, password)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("authenticate failed"))
	}
	acct, err := NewAccount(ctx, am.ScopeId, am.PublicId, loginName)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	acctId, err := newAccountId(ctx, authMethodId, loginName)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	acct.PublicId = acctId
	acct.Dn = authResult.UserDN

	if authResult.UserAttributes != nil {
		emailAttr := DefaultEmailAttribute
		fullNameAttr := DefaultFullNameAttribute

		attrMaps, err := am.convertAccountAttributeMaps(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert account attribute maps"))
		}

		for _, attrMap := range attrMaps {
			switch attrMap.ToAttribute {
			case DefaultEmailAttribute:
				emailAttr = attrMap.FromAttribute
			case DefaultFullNameAttribute:
				fullNameAttr = attrMap.FromAttribute
			default:
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid to attribute %q", attrMap.ToAttribute))
			}
		}

		found, email := caseInsensitiveAttributeSearch(emailAttr, authResult.UserAttributes)
		if found {
			acct.Email = email[0]
		}
		found, fullName := caseInsensitiveAttributeSearch(fullNameAttr, authResult.UserAttributes)
		if found {
			acct.FullName = fullName[0]
		}
	}
	if len(authResult.Groups) > 0 {
		encodedGroups, err := json.Marshal(authResult.Groups)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to encode user groups"))
		}
		acct.MemberOfGroups = string(encodedGroups)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	md, err := acct.oplog(ctx, oplog.OpType_OP_TYPE_CREATE)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// upsert account
	if err := r.writer.Create(
		ctx,
		acct,
		db.WithOnConflict(&db.OnConflict{
			Target: db.Columns{"public_id"}, // id is predictable and uses both auth method id and login name for inputs
			Action: db.SetColumns([]string{"full_name", "email", "dn", "member_of_groups"}),
		}),
		db.WithOplog(oplogWrapper, md),
	); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create/update ldap account"))
	}

	// return account
	return acct, nil
}

func caseInsensitiveAttributeSearch(attrName string, attributes map[string][]string) (bool, []string) {
	for k, v := range attributes {
		if strings.EqualFold(k, attrName) {
			return true, v
		}
	}
	return false, nil
}
