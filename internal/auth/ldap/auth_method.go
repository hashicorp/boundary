// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"google.golang.org/protobuf/proto"
)

// authMethodTableName defines an AuthMethod's table name.
const authMethodTableName = "auth_ldap_method"

// AuthMethod contains an LDAP auth method configuration.  It is owned by a
// scope. AuthMethods MUST have at least one Url. AuthMethods MAY one or zero:
// UserEntrySearchConf, a GroupEntrySearchConf, BindCredential. AuthMethods
// may have zero to many: Accounts, Certificates,
type AuthMethod struct {
	*store.AuthMethod
	tableName string
}

// NewAuthMethod creates a new in memory AuthMethod assigned to a scopeId.  The
// new auth method will have an OperationalState of Inactive.
//
// Supports the options: WithUrls, WithName, WithDescription, WithStartTLS,
// WithInsecureTLS, WithDiscoverDN, WithAnonGroupSearch, WithUpnDomain,
// WithUserSearchConf, WithGroupSearchConf, WithCertificates,
// WithBindCredential, WithDerefAliases, WithMaximumPageSize
// are the only valid options and all other options are ignored.
func NewAuthMethod(ctx context.Context, scopeId string, opt ...Option) (*AuthMethod, error) {
	const op = "ldap.NewAuthMethod"
	switch {
	case scopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			ScopeId:              scopeId,
			Name:                 opts.withName,
			Description:          opts.withDescription,
			OperationalState:     string(opts.withOperationalState), // if no option is specified, a new auth method is initially inactive
			Urls:                 opts.withUrls,
			StartTls:             opts.withStartTls,
			InsecureTls:          opts.withInsecureTls,
			DiscoverDn:           opts.withDiscoverDn,
			AnonGroupSearch:      opts.withAnonGroupSearch,
			UpnDomain:            opts.withUpnDomain,
			UserDn:               opts.withUserDn,
			UserAttr:             opts.withUserAttr,
			UserFilter:           opts.withUserFilter,
			EnableGroups:         opts.withEnableGroups,
			UseTokenGroups:       opts.withUseTokenGroups,
			GroupDn:              opts.withGroupDn,
			GroupAttr:            opts.withGroupAttr,
			GroupFilter:          opts.withGroupFilter,
			BindDn:               opts.withBindDn,
			BindPassword:         opts.withBindPassword,
			Certificates:         opts.withCertificates,
			ClientCertificate:    opts.withClientCertificate,
			ClientCertificateKey: opts.withClientCertificateKey,
			DereferenceAliases:   string(opts.withDerefAliases),
			MaximumPageSize:      uint32(opts.withMaximumPageSize),
		},
	}
	if len(opts.withAccountAttributeMap) > 0 {
		a.AccountAttributeMaps = make([]string, 0, len(opts.withAccountAttributeMap))
		for k, v := range opts.withAccountAttributeMap {
			a.AccountAttributeMaps = append(a.AccountAttributeMaps, fmt.Sprintf("%s=%s", k, v))
		}
	}

	return a, nil
}

// AllocAuthMethod makes an empty one in memory
func AllocAuthMethod() AuthMethod {
	return AuthMethod{
		AuthMethod: &store.AuthMethod{},
	}
}

// clone an AuthMethod
func (am *AuthMethod) clone() *AuthMethod {
	cp := proto.Clone(am.AuthMethod)
	return &AuthMethod{
		AuthMethod: cp.(*store.AuthMethod),
	}
}

// TableName returns the table name (func is required by gorm)
func (am *AuthMethod) TableName() string {
	if am.tableName != "" {
		return am.tableName
	}
	return authMethodTableName
}

// SetTableName sets the table name (func is required by oplog)
func (am *AuthMethod) SetTableName(n string) {
	am.tableName = n
}

// GetResourceType returns the resource type of the AuthMethod
func (am *AuthMethod) GetResourceType() resource.Type {
	return resource.AuthMethod
}

// oplog will create oplog metadata for the AuthMethod.
func (am *AuthMethod) oplog(ctx context.Context, opType oplog.OpType) (oplog.Metadata, error) {
	const op = "ldap.(AuthMethod).oplog"
	switch {
	case am == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	case opType == oplog.OpType_OP_TYPE_UNSPECIFIED:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing op type")
	case am.PublicId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case am.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	metadata := oplog.Metadata{
		"resource-public-id": []string{am.PublicId},
		"resource-type":      []string{"ldap auth method"},
		"op-type":            []string{opType.String()},
		"scope-id":           []string{am.ScopeId},
	}
	return metadata, nil
}

type convertedValues struct {
	Urls                 []*Url
	Certs                []*Certificate
	UserEntrySearchConf  *UserEntrySearchConf
	GroupEntrySearchConf *GroupEntrySearchConf
	ClientCertificate    *ClientCertificate
	BindCredential       *BindCredential
	AccountAttributeMaps []*AccountAttributeMap
	DerefAliases         *DerefAliases
}

// convertValueObjects converts the embedded value objects. It will return an
// error if the AuthMethod's public id is not set.
func (am *AuthMethod) convertValueObjects(ctx context.Context) (*convertedValues, error) {
	const op = "ldap.(AuthMethod).convertValueObjects"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	var err error
	converted := &convertedValues{}

	if converted.Urls, err = am.convertUrls(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if converted.Certs, err = am.convertCertificates(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if am.UserDn != "" || am.UserAttr != "" || am.UserFilter != "" {
		if converted.UserEntrySearchConf, err = am.convertUserEntrySearchConf(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	if am.GroupDn != "" || am.GroupAttr != "" || am.GroupFilter != "" {
		if converted.GroupEntrySearchConf, err = am.convertGroupEntrySearchConf(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	if am.ClientCertificate != "" || am.ClientCertificateKey != nil {
		if converted.ClientCertificate, err = am.convertClientCertificate(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	if am.BindDn != "" || am.BindPassword != "" {
		if converted.BindCredential, err = am.convertBindCredential(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	if converted.AccountAttributeMaps, err = am.convertAccountAttributeMaps(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if am.DereferenceAliases != "" {
		if converted.DerefAliases, err = am.convertDerefAliases(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	return converted, nil
}

// convertUrls converts any embedded URLs from []string to []*Url where each
// slice element is a *Url. It will return an error if the AuthMethod's public
// id is not set.
func (am *AuthMethod) convertUrls(ctx context.Context) ([]*Url, error) {
	const op = "ldap.(AuthMethod).convertUrls"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newValObjs := make([]*Url, 0, len(am.Urls))
	for priority, u := range am.Urls {
		addr, err := parseutil.NormalizeAddr(u)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		parsed, err := url.Parse(addr)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		obj, err := NewUrl(ctx, am.PublicId, priority+1, parsed)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newValObjs = append(newValObjs, obj)
	}
	return newValObjs, nil
}

// convertCertificates converts any embedded certificates from []string
// to []*Certificate. It will return an error if the AuthMethod's public id is
// not set.
func (am *AuthMethod) convertCertificates(ctx context.Context) ([]*Certificate, error) {
	const op = "ldap.(AuthMethod).convertCertificates"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newValObjs := make([]*Certificate, 0, len(am.Certificates))
	for _, cert := range am.Certificates {
		obj, err := NewCertificate(ctx, am.PublicId, cert)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newValObjs = append(newValObjs, obj)
	}
	return newValObjs, nil
}

// convertUserEntrySearchConf converts an embedded user entry search fields
// into an *UserEntrySearchConf type.  It will return an error if the
// AuthMethod's public id is not set.
func (am *AuthMethod) convertUserEntrySearchConf(ctx context.Context) (*UserEntrySearchConf, error) {
	const op = "ldap.(AuthMethod).convertUserEntrySearchConf"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	c, err := NewUserEntrySearchConf(ctx, am.PublicId, WithUserDn(ctx, am.UserDn), WithUserAttr(ctx, am.UserAttr), WithUserFilter(ctx, am.UserFilter))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return c, nil
}

// convertGroupEntrySearchConf converts an embedded group entry search fields
// into an *GroupEntrySearchConf type.  It will return an error if the
// AuthMethod's public id is not set.
func (am *AuthMethod) convertGroupEntrySearchConf(ctx context.Context) (*GroupEntrySearchConf, error) {
	const op = "ldap.(AuthMethod).convertGroupEntrySearchConf"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	c, err := NewGroupEntrySearchConf(ctx, am.PublicId, WithGroupDn(ctx, am.GroupDn), WithGroupAttr(ctx, am.GroupAttr), WithGroupFilter(ctx, am.GroupFilter))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return c, nil
}

// convertClientCertificate converts an embedded client certificate entry into
// an *ClientCertificate type.  It will return an error if the AuthMethod's
// public id is not set.
func (am *AuthMethod) convertClientCertificate(ctx context.Context) (*ClientCertificate, error) {
	const op = "ldap.(AuthMethod).convertClientCertificate"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing auth method id")
	}
	cc, err := NewClientCertificate(ctx, am.PublicId, am.ClientCertificateKey, am.ClientCertificate)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return cc, nil
}

// convertBindCredential converts an embedded bind credential entry into
// an *BindCredential type.  It will return an error if the AuthMethod's public
// id is not set.
func (am *AuthMethod) convertBindCredential(ctx context.Context) (*BindCredential, error) {
	const op = "ldap.(AuthMethod).convertBindCredentials"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing auth method id")
	}
	bc, err := NewBindCredential(ctx, am.PublicId, am.BindDn, []byte(am.BindPassword))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return bc, nil
}

// convertDerefAliases converts an embedded deref aliases entry into
// an *DerefAliases type.  It will return an error if the AuthMethod's public id
// is not set.
func (am *AuthMethod) convertDerefAliases(ctx context.Context) (*DerefAliases, error) {
	const op = "ldap.(AuthMethod).convertDerefAliases"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing auth method id")
	}
	da, err := NewDerefAliases(ctx, am.PublicId, DerefAliasType(am.DereferenceAliases))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return da, nil
}

// convertAccountAttributeMaps converts the embedded account attribute maps from
// []string to []*AccountAttributeMap. It will return an error if the
// AuthMethod's public id is not set or it can convert the account attribute
// maps.
func (am *AuthMethod) convertAccountAttributeMaps(ctx context.Context) ([]*AccountAttributeMap, error) {
	const op = "ldap.(AuthMethod).convertAccountAttributeMaps"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	acctAttribMaps := make([]*AccountAttributeMap, 0, len(am.AccountAttributeMaps))
	const (
		from = 0
		to   = 1
	)
	acms, err := ParseAccountAttributeMaps(ctx, am.AccountAttributeMaps...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, m := range acms {
		toClaim, err := ConvertToAccountToAttribute(ctx, m.To)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		obj, err := NewAccountAttributeMap(ctx, am.PublicId, m.From, toClaim)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		acctAttribMaps = append(acctAttribMaps, obj)
	}
	return acctAttribMaps, nil
}
