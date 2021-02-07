package oidc

import (
	"context"
	"sync"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/cap/oidc"
)

// Repository is the oidc repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	providers  map[string]*oidc.Provider
	providerMu *sync.Mutex

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
		providerMu:   &sync.Mutex{},
	}, nil
}

func (r *Repository) getProvider(ctx context.Context, authMethodId string) (*oidc.Provider, bool) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	p, ok := r.providers[authMethodId]
	return p, ok
}

func (r *Repository) setProvider(ctx context.Context, authMethodId string, p *oidc.Provider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	r.providers[authMethodId] = p
}

func (r *Repository) delProvider(ctx context.Context, authMethodId string, p *oidc.Provider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	delete(r.providers, authMethodId)
}
