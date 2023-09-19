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

// A CredentialStoreRepository provides read only information
// generic to all credential store types.
type CredentialStoreRepository struct {
	reader db.Reader
}

// NewCredentialStoreRepository creates a new CredentialStoreRepository.
func NewCredentialStoreRepository(ctx context.Context, r db.Reader) (*CredentialStoreRepository, error) {
	const op = "credential.NewCredentialStoreRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Reader")
	}

	return &CredentialStoreRepository{
		reader: r,
	}, nil
}

// Now returns the current timestamp in the DB.
func (csr *CredentialStoreRepository) Now(ctx context.Context) (time.Time, error) {
	const op = "credential.(CredentialStoreRepository).Now"
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
func (csr *CredentialStoreRepository) GetTotalItems(ctx context.Context) (int, error) {
	const op = "credential.(CredentialStoreRepository).GetTotalItems"
	rows, err := csr.reader.Query(ctx, estimateCountCredentialStores, nil)
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
func (csr *CredentialStoreRepository) ListDeletedIds(ctx context.Context, since time.Time) ([]string, error) {
	const op = "vault.(Repository).ListDeletedIds"
	var deletedCredentialStore []*deletedCredentialStore
	if err := csr.reader.SearchWhere(ctx, &deletedCredentialStore, "delete_time >= ?", []any{since}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted credential Storees"))
	}
	var credentialStoreIds []string
	for _, cs := range deletedCredentialStore {
		credentialStoreIds = append(credentialStoreIds, cs.PublicId)
	}
	return credentialStoreIds, nil
}

type deletedCredentialStore struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedCredentialStore) TableName() string {
	return "credential_store_deleted"
}
