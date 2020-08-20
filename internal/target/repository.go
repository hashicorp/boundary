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

// LookupTarget will look up a target in the repository and return the target
// and its host set ids.  If the target is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupTarget(ctx context.Context, keyWrapper wrapping.Wrapper, publicId string, opt ...Option) (Target, []string, error) {
	if publicId == "" {
		return nil, nil, fmt.Errorf("lookup target: missing private id: %w", db.ErrNilParameter)
	}
	if keyWrapper == nil {
		return nil, nil, fmt.Errorf("lookup target: missing key wrapper: %w", db.ErrNilParameter)
	}
	target := allocTargetView()
	target.PublicId = publicId
	var hostSets []string
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &target); err != nil {
				return fmt.Errorf("lookup target: failed %w for %s", err, publicId)
			}
			var err error
			if hostSets, err = fetchHostSets(ctx, read, target.PublicId); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup target: %w", err)
	}
	subType, err := target.TargetSubType()
	if err != nil {
		return nil, nil, fmt.Errorf("lookup target: %w", err)
	}
	return subType, hostSets, nil
}

func fetchHostSets(ctx context.Context, r db.Reader, targetId string) ([]string, error) {
	var hostSets []*TargetHostSet
	if err := r.SearchWhere(ctx, &hostSets, "target_id = ?", []interface{}{targetId}); err != nil {
		return nil, fmt.Errorf("fetch host sets: %w", err)
	}
	if len(hostSets) == 0 {
		return nil, nil
	}
	hs := make([]string, 0, len(hostSets))
	for _, h := range hostSets {
		hs = append(hs, h.HostSetId)
	}
	return hs, nil
}

// ListTargets in targets in a scope.  Supports the WithScopeId, WithLimit, WithTargetType options.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	opts := getOpts(opt...)
	if opts.withScopeId == "" && opts.withUserId == "" {
		return nil, fmt.Errorf("list targets: must specify either a scope id or user id: %w", db.ErrInvalidParameter)
	}
	// TODO (jimlambrt) - implement WithUserId() optional filtering.
	var where []string
	var args []interface{}
	if opts.withScopeId != "" {
		where, args = append(where, "scope_id = ?"), append(args, opts.withScopeId)
	}
	if opts.withTargetType != nil {
		where, args = append(where, "type = ?"), append(args, opts.withTargetType.String())
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
