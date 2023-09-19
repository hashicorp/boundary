// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// A CredentialRepository provides read only information
// generic to all credential types.
type CredentialRepository struct {
	reader db.Reader
}

// NewCredentialRepository creates a new CredentialRepository.
func NewCredentialRepository(ctx context.Context, r db.Reader) (*CredentialRepository, error) {
	const op = "credential.NewCredentialRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Reader")
	}

	return &CredentialRepository{
		reader: r,
	}, nil
}

// Now returns the current timestamp in the DB.
func (csr *CredentialRepository) Now(ctx context.Context) (time.Time, error) {
	const op = "credential.(CredentialRepository).Now"
	rows, err := csr.reader.Query(ctx, "select current_timestamp", nil)
	if err != nil {
		return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
	}
	var now time.Time
	for rows.Next() {
		if err := csr.reader.ScanRows(ctx, rows, &now); err != nil {
			return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
		}
	}
	return now, nil
}

// GetTotalItems returns an estimate of the total number of items in the root aggregate credential store table.
func (csr *CredentialRepository) GetTotalItems(ctx context.Context) (int, error) {
	const op = "credential.(CredentialRepository).GetTotalItems"
	rows, err := csr.reader.Query(ctx, estimateCountCredentials, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential stores"))
	}
	var count int
	for rows.Next() {
		if err := csr.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential stores"))
		}
	}
	return count, nil
}

// ListDeletedIds lists the public IDs of any credential stores deleted since the timestamp provided.
func (csr *CredentialRepository) ListDeletedIds(ctx context.Context, since time.Time) ([]string, error) {
	const op = "vault.(Repository).ListDeletedIds"
	var deletedCredential []*deletedCredential
	if err := csr.reader.SearchWhere(ctx, &deletedCredential, "delete_time >= ?", []any{since}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted credential Storees"))
	}
	var credentialStoreIds []string
	for _, cs := range deletedCredential {
		credentialStoreIds = append(credentialStoreIds, cs.PublicId)
	}
	return credentialStoreIds, nil
}

type deletedCredential struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedCredential) TableName() string {
	return "credential_deleted"
}
