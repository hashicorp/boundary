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

// A CredentialLibraryRepository provides read only information
// generic to all credential store types.
type CredentialLibraryRepository struct {
	reader db.Reader
}

// NewCredentialLibraryRepository creates a new CredentialLibraryRepository.
func NewCredentialLibraryRepository(ctx context.Context, r db.Reader) (*CredentialLibraryRepository, error) {
	const op = "credential.NewCredentialLibraryRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Reader")
	}

	return &CredentialLibraryRepository{
		reader: r,
	}, nil
}

// Now returns the current timestamp in the DB.
func (clr *CredentialLibraryRepository) Now(ctx context.Context) (time.Time, error) {
	const op = "credential.(CredentialLibraryRepository).Now"
	rows, err := clr.reader.Query(ctx, "select current_timestamp", nil)
	if err != nil {
		return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
	}
	var now time.Time
	for rows.Next() {
		if err := clr.reader.ScanRows(ctx, rows, &now); err != nil {
			return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
		}
	}
	return now, nil
}

// GetTotalItems returns an estimate of the total number of items in the root aggregate credential library table.
func (clr *CredentialLibraryRepository) GetTotalItems(ctx context.Context) (int, error) {
	const op = "credential.(CredentialLibraryRepository).GetTotalItems"
	rows, err := clr.reader.Query(ctx, estimateCountCredentialLibraries, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential libraries"))
	}
	var count int
	for rows.Next() {
		if err := clr.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential libraries"))
		}
	}
	return count, nil
}

// ListDeletedIds lists the public IDs of any credential libraries deleted since the timestamp provided.
func (clr *CredentialLibraryRepository) ListDeletedIds(ctx context.Context, since time.Time) ([]string, error) {
	const op = "credential.(CredentialLibraryRepository).ListDeletedIds"
	var deletedCredentialLibraries []*deletedCredentialLibrary
	if err := clr.reader.SearchWhere(ctx, &deletedCredentialLibraries, "delete_time >= ?", []any{since}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted credential libraries"))
	}
	var credentialLibraryIds []string
	for _, cl := range deletedCredentialLibraries {
		credentialLibraryIds = append(credentialLibraryIds, cl.PublicId)
	}
	return credentialLibraryIds, nil
}

type deletedCredentialLibrary struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedCredentialLibrary) TableName() string {
	return "credential_library_deleted"
}
