package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
)

// LookupAuthMethod will lookup an auth method in the repo, along with its
// associated Value Objects of SigningAlgs, CallbackUrls, AudClaims and
// Certificates. If it's not found, it will return nil, nil.  The
// WithUnauthenticatedUser options is supported and all other options are
// ignored.
func (r *Repository) LookupAuthMethod(ctx context.Context, publicId string, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).LookupAuthMethod"
	if publicId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	opts := getOpts(opt...)
	fmt.Println()
	authMethods, err := r.getAuthMethods(ctx, publicId, nil, WithUnauthenticatedUser(opts.withUnauthenticatedUser))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	if len(authMethods) > 1 {
		return nil, errors.New(errors.NotSpecificIntegrity, op, fmt.Sprintf("auth method id %s returned more than one result", publicId))
	}
	if len(authMethods) == 0 {
		return nil, nil
	}
	return authMethods[0], nil
}

// ListAuthMethods returns a slice of AuthMethods for the scopeId. The
// WithUnauthenticatedUser, WithLimit and WithOrder options are supported and
//  all other options are ignored.
func (r *Repository) ListAuthMethods(ctx context.Context, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	const op = "oidc.(Repository).ListAuthMethods"
	if len(scopeIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing scope IDs")
	}
	authMethods, err := r.getAuthMethods(ctx, "", scopeIds, opt...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return authMethods, nil
}

// getAuthMethods allows the caller to either lookup a specific AuthMethod via
// its id or search for a set AuthMethods within a set of scopes.  Passing both
// scopeIds and a authMethodId is an error. The WithUnauthenticatedUser,
// WithLimit and WithOrder options are supported and all other options are
// ignored.
//
// The AuthMethod returned has its value objects populated (SigningAlgs,
// CallbackUrls, AudClaims and Certificates)
//
// When no record is found it returns nil, nil
func (r *Repository) getAuthMethods(ctx context.Context, authMethodId string, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	const op = "oidc.(Repository).getAuthMethods"
	if authMethodId == "" && len(scopeIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing search criteria: both auth method id and Scope IDs are empty")
	}
	if authMethodId != "" && len(scopeIds) > 0 {
		return nil, errors.New(errors.InvalidParameter, op, "searching for both an auth method id and Scope IDs is not supported")
	}

	const aggregateDelimiter = "|"

	dbArgs := []db.Option{}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbArgs = append(dbArgs, db.WithLimit(limit))

	if opts.withOrderClause != "" {
		dbArgs = append(dbArgs, db.WithOrder(opts.withOrderClause))
	}

	var args []interface{}
	var where []string
	switch {
	case authMethodId != "":
		where, args = append(where, "public_id = ?"), append(args, authMethodId)
	default:
		where, args = append(where, "scope_id in(?)"), append(args, scopeIds)
	}

	if opts.withUnauthenticatedUser {
		where, args = append(where, "state = ?"), append(args, string(ActivePublicState))
	}

	var aggAuthMethods []*authMethodAgg
	err := r.reader.SearchWhere(ctx, &aggAuthMethods, strings.Join(where, " and "), args, dbArgs...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	if len(aggAuthMethods) == 0 { // we're done if nothing is found.
		return nil, nil
	}

	authMethods := make([]*AuthMethod, 0, len(aggAuthMethods))
	for _, agg := range aggAuthMethods {
		databaseWrapper, err := r.kms.GetWrapper(ctx, agg.ScopeId, kms.KeyPurposeDatabase, kms.WithKeyId(agg.KeyId))
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := structwrapping.UnwrapStruct(ctx, databaseWrapper, agg, nil); err != nil {
			return nil, errors.Wrap(err, op, errors.WithCode(errors.Decrypt))
		}
		am := AllocAuthMethod()
		am.PublicId = agg.PublicId
		am.ScopeId = agg.ScopeId
		am.Name = agg.Name
		am.Description = agg.Description
		am.CreateTime = agg.CreateTime
		am.UpdateTime = agg.UpdateTime
		am.Version = agg.Version
		am.OperationalState = agg.State
		am.DiscoveryUrl = agg.DiscoveryUrl
		am.ClientId = agg.ClientId
		am.CtClientSecret = agg.CtClientSecret
		am.ClientSecret = agg.ClientSecret
		am.ClientSecretHmac = agg.ClientSecretHmac
		am.KeyId = agg.KeyId
		am.MaxAge = int32(agg.MaxAge)
		if agg.Algs != "" {
			am.SigningAlgs = strings.Split(agg.Algs, aggregateDelimiter)
		}
		if agg.Callbacks != "" {
			am.CallbackUrls = strings.Split(agg.Callbacks, aggregateDelimiter)
		}
		if agg.Auds != "" {
			am.AudClaims = strings.Split(agg.Auds, aggregateDelimiter)
		}
		if agg.Certs != "" {
			am.Certificates = strings.Split(agg.Certs, aggregateDelimiter)
		}
		authMethods = append(authMethods, &am)
	}
	return authMethods, nil
}

// authMethodAgg is a view that aggregates the auth method's value objects in to
// string fields delimited with the aggregateDelimiter of "|"
type authMethodAgg struct {
	PublicId         string `gorm:"primary_key"`
	ScopeId          string
	Name             string
	Description      string
	CreateTime       *timestamp.Timestamp
	UpdateTime       *timestamp.Timestamp
	Version          uint32
	State            string
	DiscoveryUrl     string
	ClientId         string
	CtClientSecret   []byte `gorm:"column:client_secret;not_null" wrapping:"ct,client_secret"`
	ClientSecret     string `gorm:"-" wrapping:"pt,client_secret"`
	ClientSecretHmac string
	KeyId            string
	MaxAge           int
	Algs             string
	Callbacks        string
	Auds             string
	Certs            string
}

// TableName returns the table name for gorm
func (agg *authMethodAgg) TableName() string { return "oidc_auth_method_with_value_obj" }
