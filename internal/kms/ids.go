package kms

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	RootKeyPrefix            = "krk"
	RootKeyVersionPrefix     = "krkv"
	DatabaseKeyPrefix        = "kdk"
	DatabaseKeyVersionPrefix = "kdkv"
	OplogKeyPrefix           = "kopk"
	OplogKeyVersionPrefix    = "kopkv"
	TokenKeyPrefix           = "ktk"
	TokenKeyVersionPrefix    = "ktv"
	SessionKeyPrefix         = "ksk"
	SessionKeyVersionPrefix  = "kskv"
	OidcKeyPrefix            = "koidck"
	OidcKeyVersionPrefix     = "koidckv"
)

func newRootKeyId() (string, error) {
	const op = "kms.newRootKeyId"
	id, err := db.NewPublicId(RootKeyPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newRootKeyVersionId() (string, error) {
	const op = "kms.newRootKeyVersionId"
	id, err := db.NewPublicId(RootKeyVersionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newDatabaseKeyId() (string, error) {
	const op = "kms.newDatabaseKeyId"
	id, err := db.NewPublicId(DatabaseKeyPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newDatabaseKeyVersionId() (string, error) {
	const op = "kms.newDatabaseKeyVersionId"
	id, err := db.NewPublicId(DatabaseKeyVersionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newOplogKeyId() (string, error) {
	const op = "kms.newOplogKeyId"
	id, err := db.NewPublicId(OplogKeyPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newOplogKeyVersionId() (string, error) {
	const op = "kms.newOplogKeyVersionId"
	id, err := db.NewPublicId(OplogKeyVersionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newTokenKeyId() (string, error) {
	const op = "kms.newTokenKeyId"
	id, err := db.NewPublicId(TokenKeyPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newTokenKeyVersionId() (string, error) {
	const op = "kms.newTokenKeyVersionId"
	id, err := db.NewPublicId(TokenKeyVersionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newSessionKeyId() (string, error) {
	const op = "kms.newSessionKeyId"
	id, err := db.NewPublicId(SessionKeyPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newSessionKeyVersionId() (string, error) {
	const op = "kms.newSessionKeyVersionId"
	id, err := db.NewPublicId(SessionKeyVersionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newOidcKeyId() (string, error) {
	const op = "kms.newOidcKeyId"
	id, err := db.NewPublicId(OidcKeyPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newOidcKeyVersionId() (string, error) {
	const op = "kms.newOidcKeyVersionId"
	id, err := db.NewPublicId(OidcKeyVersionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}
