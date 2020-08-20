package target

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

var (
	ErrMetadataScopeNotFound = errors.New("scope not found for metadata")
)

// Repository is the target database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new target Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if kms == nil {
		return nil, errors.New("error creating db repository with nil kms")
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

// LookupTarget will look up a target in the repository.  If the target is not
// found, it will return nil, nil.  No options are currently supported.
func (r *Repository) LookupTarget(ctx context.Context, keyWrapper wrapping.Wrapper, publicId string, opt ...Option) (Target, error) {
	if publicId == "" {
		return nil, fmt.Errorf("lookup target: missing private id: %w", db.ErrNilParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("lookup target: missing key wrapper: %w", db.ErrNilParameter)
	}
	target := allocTargetView()
	target.PublicId = publicId
	if err := r.reader.LookupById(ctx, &target); err != nil {
		return nil, fmt.Errorf("lookup target: failed %w for %s", err, publicId)
	}
	subType, err := target.TargetSubType()
	if err != nil {
		return nil, fmt.Errorf("lookup target: %w", err)
	}
	return subType, nil
}

// ListTargets in targets in a scope.  Supports the WithScopeId, WithUserId, WithLimit, WithTargetType options.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	opts := getOpts(opt...)
	if opts.withScopeId == "" && opts.withUserId == "" {
		return nil, fmt.Errorf("list targets: must specify either a scope id or user id: %w", db.ErrInvalidParameter)
	}
	var where []string
	var args []interface{}
	if opts.withScopeId != "" {
		where, args = append(where, "scope_id = ?"), append(args, opts.withScopeId)
	}
	if opts.withTargetType != nil {
		where, args = append(where, "type = ?"), append(args, opts.withTargetType)
	}

	var foundTargets []*targetView
	err := r.list(ctx, &foundTargets, strings.Join(where, " and "), args, opt...)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}

	targets := make([]Target, 0, len(foundTargets))

	for _, t := range foundTargets {
		subType, err := t.TargetSubType()
		if err != nil {
			return nil, fmt.Errorf("list targets: %w", err)
		}
		targets = append(targets, subType)
	}
	return targets, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	return r.reader.SearchWhere(ctx, resources, where, args, dbOpts...)
}
