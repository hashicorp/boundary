package password

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// A Repository stores and retrieves the persistent types in the password
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	keyId  string
	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

type Builder struct {
	repo Repository
}

type ReadWriter interface {
	db.Reader
	db.Writer
}

func (b *Builder) ReadWriter(rw ReadWriter) *Builder {
	b.repo.reader = rw
	b.repo.writer = rw
	return b
}

func (b *Builder) Reader(r db.Reader) *Builder {
	b.repo.reader = r
	return b
}

func (b *Builder) Writer(w db.Writer) *Builder {
	b.repo.writer = w
	return b
}

func (b *Builder) Kms(k *kms.Kms) *Builder {
	b.repo.kms = k
	return b
}

func (b *Builder) KeyId(k string) *Builder {
	b.repo.keyId = k
	return b
}

func (b *Builder) DefaultLimit(l int) *Builder {
	b.repo.defaultLimit = l
	return b
}

func (b *Builder) LookupScopeIdForResource(ctx context.Context, id string) (string, error) {
	const op = "password.(Builder).ScopeForResource"
	switch {
	case b.repo.reader == nil:
		return "", errors.New(errors.InvalidParameter, op, "missing db.Reader")
	case !strings.HasPrefix(id, AuthMethodPrefix) &&
			!strings.HasPrefix(id, intglobals.OldPasswordAccountPrefix) &&
			!strings.HasPrefix(id, intglobals.NewPasswordAccountPrefix):
		return "", errors.New(errors.InvalidParameter, op, "unrecognized resource id  prefix")
	}

	am := allocAuthMethod()
	am.PublicId = id
	if strings.HasPrefix(id, intglobals.OldPasswordAccountPrefix) || strings.HasPrefix(id, intglobals.NewPasswordAccountPrefix) {
		acct := allocAccount()
		acct.PublicId = id
		if err := b.repo.reader.LookupById(ctx, acct); err != nil {
			return "", errors.Wrap(err, op, errors.WithMsg("looking up account"))
		}
		am.PublicId = acct.GetAuthMethodId()
	}

	if err := b.repo.reader.LookupById(ctx, am); err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("looking up auth method"))
	}
	return am.GetScopeId(), nil
}

func (b *Builder) Build() (*Repository, error) {
	const op = "password.(Builder).Build"
	switch {
	case b.repo.reader == nil:
		return nil, errors.New(errors.InvalidParameter, op, "missing db.Reader")
	case b.repo.writer == nil:
		return nil, errors.New(errors.InvalidParameter, op, "missing db.Writer")
	case b.repo.kms == nil:
		return nil, errors.New(errors.InvalidParameter, op, "missing kms")
	case !strings.HasPrefix(b.repo.keyId, scope.Org.Prefix()) &&
			!strings.HasPrefix(b.repo.keyId, scope.Project.Prefix()) &&
			b.repo.keyId != scope.Global.Prefix():
		return nil, errors.New(errors.InvalidParameter, op, "unrecognized kms key id")
	}

	if b.repo.defaultLimit == 0 {
		// zero signals the boundary defaults should be used.
		b.repo.defaultLimit = db.DefaultLimit
	}
	return &b.repo, nil
}


func (r *Repository) keyFor(ctx context.Context, p kms.KeyPurpose, opts ...kms.Option) (wrapping.Wrapper, error) {
	return r.kms.GetWrapper(ctx, r.keyId, p, opts...)
}

func contains(ss []string, t string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}
