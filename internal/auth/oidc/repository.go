package oidc

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
)

// Repository is the oidc repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new oidc Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "oidc.NewRepository"
	if r == nil {
		return nil, errors.New(errors.InvalidParameter, op, "reader is nil")
	}
	if w == nil {
		return nil, errors.New(errors.InvalidParameter, op, "writer is nil")
	}
	if kms == nil {
		return nil, errors.New(errors.InvalidParameter, op, "kms is nil")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}

// getAuthMethods allows the caller to either lookup a specific AuthMethod via
// its id or search for a set AuthMethods within a set of scopes.  Passing both
// scopeIds and a authMethodId is an error. The WithLimit and WithOrder options
// are supported and all other options are ignored.
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
		am.State = agg.State
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
