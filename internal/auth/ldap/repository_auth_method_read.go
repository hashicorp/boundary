// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
)

// LookupAuthMethod will lookup an auth method in the repo, along with its
// associated Value Objects of SigningAlgs, CallbackUrls, AudClaims and
// Certificates. If it's not found, it will return nil, nil.  The
// WithUnauthenticatedUser options is supported and all other options are
// ignored.
func (r *Repository) LookupAuthMethod(ctx context.Context, publicId string, opt ...Option) (*AuthMethod, error) {
	const op = "ldap.(Repository).LookupAuthMethod"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return r.lookupAuthMethod(ctx, publicId, WithUnauthenticatedUser(ctx, opts.withUnauthenticatedUser))
}

// ListAuthMethods returns a slice of AuthMethods for the scopeId. Supported options:
//   - auth.WithLimit
//   - auth.WithStartPageAfterItem
//
// This method uses the auth domain options and auth.AuthMethod type to allow it to
// be called from the auth package. If it was using the ldap option type we would
// run into a cyclical dependency issue.
func (r *Repository) ListAuthMethods(ctx context.Context, scopeIds []string, opt ...auth.Option) ([]auth.AuthMethod, error) {
	const op = "ldap.(Repository).ListAuthMethods"
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope IDs")
	}
	// Convert the auth package options to the ldap options,
	// since we share r.getAuthMethods with lookupAuthMethod.
	opts, err := auth.GetOpts(opt...)
	if err != nil {
		return nil, err
	}
	newOpts := []Option{
		WithUnauthenticatedUser(ctx, opts.WithUnauthenticatedUser),
	}
	if opts.WithLimit != 0 {
		newOpts = append(newOpts, WithLimit(ctx, opts.WithLimit))
	}
	if opts.WithStartPageAfterItem != nil {
		newOpts = append(newOpts, WithStartPageAfterItem(ctx, opts.WithStartPageAfterItem))
	}
	authMethods, err := r.getAuthMethods(ctx, "", scopeIds, newOpts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// Convert back to the auth types
	var ams []auth.AuthMethod
	for _, am := range authMethods {
		ams = append(ams, am)
	}
	return ams, nil
}

// lookupAuthMethod will lookup a single auth method
func (r *Repository) lookupAuthMethod(ctx context.Context, authMethodId string, opt ...Option) (*AuthMethod, error) {
	const op = "ldap.(Repository).lookupAuthMethod"
	var err error
	ams, err := r.getAuthMethods(ctx, authMethodId, nil, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch {
	case len(ams) == 0:
		return nil, nil // not an error to return no rows for a "lookup"
	case len(ams) > 1:
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("%s matched more than 1 ", authMethodId))
	default:
		return ams[0], nil
	}
}

// getAuthMethods allows the caller to either lookup a specific AuthMethod via
// its id or search for a set AuthMethods within a set of scopes.  Passing both
// scopeIds and a authMethod is an error. The WithUnauthenticatedUser,
// WithLimit and WithOrder options are supported and all other options are
// ignored.
//
// The AuthMethod returned has its value objects populated (SigningAlgs,
// CallbackUrls, AudClaims and Certificates).  The AuthMethod returned has its
// IsPrimaryAuthMethod bool set.
//
// When no record is found it returns nil, nil
func (r *Repository) getAuthMethods(ctx context.Context, authMethodId string, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	const op = "ldap.(Repository).getAuthMethods"
	if authMethodId == "" && len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing search criteria: both auth method id and scope ids are empty")
	}
	if authMethodId != "" && len(scopeIds) > 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "searching for both an auth method id and scope ids is not supported")
	}

	const aggregateDelimiter = "|"

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	var args []any
	var whereClause string
	var inClauses []string
	switch {
	case authMethodId != "":
		whereClause += "public_id = @auth_method_id"
		args = append(args, sql.Named("auth_method_id", authMethodId))
	default:
		for i, scopeId := range scopeIds {
			arg := "scope_id_" + strconv.Itoa(i)
			inClauses = append(inClauses, "@"+arg)
			args = append(args, sql.Named(arg, scopeId))
		}
		inClause := strings.Join(inClauses, ", ")
		whereClause += "scope_id in (" + inClause + ")"
	}

	if opts.withUnauthenticatedUser {
		// the caller is asking for a list of auth methods which can be returned
		// to unauthenticated users (so they can authen).
		whereClause += " and state = @active_public_state"
		args = append(args, sql.Named("active_public_state", string(ActivePublicState)))
	}

	// Ordering and pagination are tightly coupled.
	// We order by update_time ascending so that new
	// and updated items appear at the end of the pagination.
	// We need to further order by public_id to distinguish items
	// with identical update times.
	withOrder := "update_time asc, public_id asc"
	if opts.withStartPageAfterItem != nil {
		// Now that the order is defined, we can use a simple where
		// clause to only include items updated since the specified
		// start of the page. We use greater than or equal for the update
		// time as there may be items with identical update_times. We
		// then use PublicId as a tiebreaker.
		args = append(args,
			sql.Named("after_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("after_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
		whereClause = "(" + whereClause + ") and (update_time > @after_item_update_time or (update_time = @after_item_update_time and public_id > @after_item_id))"
	}

	var aggAuthMethods []*authMethodAgg
	err = r.reader.SearchWhere(ctx, &aggAuthMethods, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if len(aggAuthMethods) == 0 { // we're done if nothing is found.
		return nil, nil
	}

	authMethods := make([]*AuthMethod, 0, len(aggAuthMethods))
	for _, agg := range aggAuthMethods {

		ccKey := struct {
			Ct []byte `wrapping:"ct,certificate_key"`
			Pt []byte `wrapping:"pt,certificate_key"`
		}{Ct: agg.ClientCertificateKey}
		if agg.ClientCertificateKey != nil {
			ccWrapper, err := r.kms.GetWrapper(ctx, agg.ScopeId, kms.KeyPurposeDatabase, kms.WithKeyId(agg.ClientCertificateKeyId))
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to get database wrapper for client certificate key"))
			}
			if err := structwrapping.UnwrapStruct(ctx, ccWrapper, &ccKey); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("failed to decrypt client certificate key"))
			}
		}
		bindPassword := struct {
			Ct []byte `wrapping:"ct,password"`
			Pt []byte `wrapping:"pt,password"`
		}{Ct: agg.BindPassword}
		if agg.BindPassword != nil {
			bindWrapper, err := r.kms.GetWrapper(ctx, agg.ScopeId, kms.KeyPurposeDatabase, kms.WithKeyId(agg.BindKeyId))
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to get database wrapper for bind password"))
			}
			if err := structwrapping.UnwrapStruct(ctx, bindWrapper, &bindPassword); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("failed to decrypt bind password"))
			}
		}
		am := AllocAuthMethod()
		am.PublicId = agg.PublicId
		am.ScopeId = agg.ScopeId
		am.IsPrimaryAuthMethod = agg.IsPrimaryAuthMethod
		am.Name = agg.Name
		am.Description = agg.Description
		am.CreateTime = agg.CreateTime
		am.UpdateTime = agg.UpdateTime
		am.Version = agg.Version
		am.OperationalState = agg.State
		am.StartTls = agg.StartTLS
		am.InsecureTls = agg.InsecureTLS
		am.DiscoverDn = agg.DiscoverDn
		am.AnonGroupSearch = agg.AnonGroupSearch
		am.EnableGroups = agg.EnableGroups
		am.UseTokenGroups = agg.UseTokenGroups
		am.UpnDomain = agg.UpnDomain
		if agg.Urls != "" {
			am.Urls = strings.Split(agg.Urls, aggregateDelimiter)
		}
		if agg.Certs != "" {
			am.Certificates = strings.Split(agg.Certs, aggregateDelimiter)
		}
		am.UserDn = agg.UserDn
		am.UserAttr = agg.UserAttr
		am.UserFilter = agg.UserFilter
		am.GroupDn = agg.GroupDn
		am.GroupAttr = agg.GroupAttr
		am.GroupFilter = agg.GroupFilter
		am.ClientCertificateKey = ccKey.Pt
		am.ClientCertificateKeyHmac = agg.ClientCertificateKeyHmac
		am.ClientCertificate = string(agg.ClientCertificateCert)
		am.BindDn = agg.BindDn
		am.BindPassword = string(bindPassword.Pt)
		am.BindPasswordHmac = agg.BindPasswordHmac
		if agg.AccountAttributeMap != "" {
			am.AccountAttributeMaps = strings.Split(agg.AccountAttributeMap, aggregateDelimiter)
		}
		am.DereferenceAliases = agg.DereferenceAliases
		am.MaximumPageSize = agg.MaximumPageSize
		authMethods = append(authMethods, &am)
	}
	return authMethods, nil
}

// ListDeletedAuthMethodIds lists the public IDs of any auth methods deleted since the timestamp provided.
func (r *Repository) ListDeletedAuthMethodIds(ctx context.Context, since time.Time, options ...auth.Option) ([]string, error) {
	const op = "ldap.(Repository).ListDeletedAuthMethodIds"
	opts, err := auth.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	rd := r.reader
	if opts.WithReader != nil {
		rd = opts.WithReader
	}
	var deletedAuthMethods []*deletedAuthMethod
	if err := rd.SearchWhere(ctx, &deletedAuthMethods, "delete_time >= ?", []any{since}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted auth methods"))
	}
	var authMethodIds []string
	for _, am := range deletedAuthMethods {
		authMethodIds = append(authMethodIds, am.PublicId)
	}
	return authMethodIds, nil
}

// EstimatedAuthMethodCount returns and estimate of the total number of items in the auth methods table.
func (r *Repository) EstimatedAuthMethodCount(ctx context.Context) (int, error) {
	const op = "ldap.(Repository).EstimatedAuthMethodCount"
	rows, err := r.reader.Query(ctx, estimateCountLdapAuthMethods, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth methods"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth methods"))
		}
	}
	return count, nil
}

// authMethodAgg is a view that aggregates the auth method's value objects. If
// the value object can have multiple values like Urls and Certs, then the
// string field is delimited with the aggregateDelimiter of "|"
type authMethodAgg struct {
	PublicId                 string `gorm:"primary_key"`
	ScopeId                  string
	IsPrimaryAuthMethod      bool
	Name                     string
	Description              string
	CreateTime               *timestamp.Timestamp
	UpdateTime               *timestamp.Timestamp
	Version                  uint32
	State                    string
	StartTLS                 bool
	InsecureTLS              bool
	DiscoverDn               bool
	AnonGroupSearch          bool
	UpnDomain                string
	Urls                     string
	Certs                    string
	UserDn                   string
	UserAttr                 string
	UserFilter               string
	EnableGroups             bool
	UseTokenGroups           bool
	GroupDn                  string
	GroupAttr                string
	GroupFilter              string
	ClientCertificateKey     []byte
	ClientCertificateKeyHmac []byte
	ClientCertificateKeyId   string
	ClientCertificateCert    []byte
	BindDn                   string
	BindPassword             []byte
	BindPasswordHmac         []byte
	BindKeyId                string
	AccountAttributeMap      string
	DereferenceAliases       string
	MaximumPageSize          uint32
}

// TableName returns the table name for gorm
func (agg *authMethodAgg) TableName() string { return "ldap_auth_method_with_value_obj" }
