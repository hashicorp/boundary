package kms

import (
	"context"
	"io"
	"sync"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

type Kms struct {
	underlying *wrappingKms.Kms

	derivedPurposeCache sync.Map
}

func New(ctx context.Context, reader *db.Db, writer *db.Db, _ ...Option) (*Kms, error) {
	const op = "kms.(Kms).New"
	purposes := make([]wrappingKms.KeyPurpose, 0, len(ValidDekPurposes()))
	for _, p := range ValidDekPurposes() {
		purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
	}
	r := dbw.New(reader.UnderlyingDB())
	w := dbw.New(writer.UnderlyingDB())
	k, err := wrappingKms.New(r, w, purposes, wrappingKms.WithCache(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}
	return &Kms{underlying: k}, nil
}

func NewUsingReaderWriter(ctx context.Context, reader db.Reader, writer db.Writer, _ ...Option) (*Kms, error) {
	const op = "kms.(Kms).New"
	purposes := make([]wrappingKms.KeyPurpose, 0, len(ValidDekPurposes()))
	for _, p := range ValidDekPurposes() {
		purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
	}
	r, err := convertToDb(ctx, reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	w, err := convertToDb(ctx, writer)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	k, err := wrappingKms.New(r, w, purposes, wrappingKms.WithCache(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}
	return &Kms{underlying: k}, nil
}

func convertToDb(ctx context.Context, r interface{}) (*dbw.RW, error) {
	const op = "kms.convertToDb"
	readerDb, ok := r.(*db.Db)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to convert to db.DB")
	}
	return dbw.New(readerDb.UnderlyingDB()), nil
}

func (k *Kms) AddExternalWrappers(ctx context.Context, opt ...Option) error {
	const op = "kms.(Kms).AddExternalWrappers"

	opts := getOpts(opt...)
	if opts.withRootWrapper != nil {
		if err := k.underlying.AddExternalWrapper(ctx, wrappingKms.KeyPurposeRootKey, opts.withRootWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add root wrapper"))
		}
	}
	if opts.withWorkerAuthWrapper != nil {
		if err := k.underlying.AddExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeWorkerAuth.String()), opts.withRootWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add worker auth wrapper"))
		}
	}
	if opts.withRecoveryWrapper != nil {
		if err := k.underlying.AddExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeRecovery.String()), opts.withRootWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add recovery wrapper"))
		}
	}
	return nil
}

func (k *Kms) GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error) {
	const op = "kms.(Kms).GetWrapper"
	opts := getOpts(opt...)
	w, err := k.underlying.GetWrapper(ctx, scopeId, wrappingKms.KeyPurpose(purpose.String()), wrappingKms.WithKeyId(opts.withKeyId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get wrapper"))
	}
	return w, err
}

func (k *Kms) GetExternalWrappers(ctx context.Context) *ExternalWrappers {
	const op = "kms.(Kms).GetExternalWrappers"
	ret := &ExternalWrappers{}
	if root, err := k.underlying.GetExternalRootWrapper(); err == nil {
		ret.root = root
	}
	if workerAuth, err := k.underlying.GetExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeWorkerAuth.String())); err == nil {
		ret.workerAuth = workerAuth
	}
	if recovery, err := k.underlying.GetExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeRecovery.String())); err == nil {
		ret.recovery = recovery
	}
	return ret
}

func (k *Kms) GetDerivedPurposeCache() *sync.Map {
	return &k.derivedPurposeCache
}

func (k *Kms) ReconcileKeys(ctx context.Context, randomReader io.Reader, opt ...Option) error {
	panic("todo")
}

func (k *Kms) CreateKeys(ctx context.Context, scopeId string, opt ...Option) error {
	const op = "kms.(Kms).CreateKeysTx"
	opts := getOpts(opt...)

	kmsOpts := []wrappingKms.Option{wrappingKms.WithRandomReader(opts.withRandomReader)}
	switch {
	case !isNil(opts.withReader) && isNil(opts.withWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	case isNil(opts.withReader) && !isNil(opts.withWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	case !isNil(opts.withReader) && !isNil(opts.withWriter):
		r, err := convertToDb(ctx, opts.withReader)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert reader"))
		}
		w, err := convertToDb(ctx, opts.withWriter)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert writer"))
		}
		kmsOpts = append(kmsOpts, wrappingKms.WithReaderWriter(r, w))
	}
	purposes := make([]wrappingKms.KeyPurpose, 0, len(ValidDekPurposes()))
	for _, p := range ValidDekPurposes() {
		purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
	}
	if err := k.underlying.CreateKeys(ctx, scopeId, purposes, kmsOpts...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
