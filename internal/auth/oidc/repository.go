package oidc

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
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

// requestWrapper finds the wrapper to use when encrypting/decrypting oidc
// Request.State and Request.Token.  It first checks the cache of derived wrappers.
// If it's not found in the cache it generates a key based on the scope's oidc DEK, using
// the scopeId and authMethodId as salt and info for derivation, and returns
// a wrapper for that newly derived key.  It supports the WithKeyId(...) option
// which allows you to specify which oidc DEK to use vs just using the latest version
// of the DEK.
func (r *Repository) requestWrapper(ctx context.Context, scopeId, authMethodId string, opt ...Option) (wrapping.Wrapper, error) {
	const op = "oidc.(Repository).oidcWrapper"
	if scopeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing scope id")
	}
	if authMethodId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	opts := getOpts(opt...)
	// get a specific oidcWrapper using the WithKeyId(...) option
	oidcWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOidc, kms.WithKeyId(opts.withKeyId))
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oidc wrapper"))
	}

	// What derived key are we looking for?
	keyId := derivedKeyId(derivedKeyPurposeState, oidcWrapper.KeyID(), authMethodId)
	derivedWrapper, ok := r.kms.GetDerivedPurposeCache().Load(keyId)
	if ok {
		return derivedWrapper.(*aead.Wrapper), nil
	}

	// okay, I guess we need to derive a new key for this combo of oidcWrapper and authMethodId
	reader, err := kms.NewDerivedReader(oidcWrapper, 32, []byte(authMethodId), []byte(scopeId))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	privKey, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, errors.New(errors.Encrypt, op, "unable to generate key", errors.WithWrap(err))
	}
	wrapper := aead.NewWrapper(nil)
	if _, err := wrapper.SetConfig(map[string]string{
		"key_id": keyId,
	}); err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("error setting config on aead wrapper in auth method %s", authMethodId)))
	}
	if err := wrapper.SetAESGCMKeyBytes(privKey); err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("error setting key bytes on aead wrapper in auth method %s", authMethodId)))
	}
	// store the derived key in our cache
	r.kms.GetDerivedPurposeCache().Store(keyId, wrapper)

	return wrapper, nil
}

func derivedKeyId(purpose derivedKeyPurpose, wrapperKeyId, authMethodId string) string {
	return fmt.Sprintf("%s.%s.%s", purpose.String(), wrapperKeyId, authMethodId)
}

type derivedKeyPurpose uint

const (
	derivedKeyPurposeUnknown = iota
	derivedKeyPurposeState
)

func (k derivedKeyPurpose) String() string {
	switch k {
	case derivedKeyPurposeState:
		return "oidc_state"
	default:
		return "oidc_unknown"
	}
}
