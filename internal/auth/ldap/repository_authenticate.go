// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"encoding/json"
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
		ClientTLSKey:          string(am.ClientCertificateKey),
		ClientTLSCert:         am.ClientCertificate,
		BindDN:                am.BindDn,
		BindPassword:          am.BindPassword,
		RequestTimeout:        DefaultRequestTimeout,
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
		found, email := caseInsensitiveAttributeSearch(DefaultEmailAttribute, authResult.UserAttributes)
		if found {
			acct.Email = email[0]
		}
		found, fullName := caseInsensitiveAttributeSearch(DefaultFullNameAttribute, authResult.UserAttributes)
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

	databaseWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeDatabase)
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
		db.WithOplog(databaseWrapper, md),
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
