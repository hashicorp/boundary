// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// An AccountRepository provides read only information
// generic to all account store types.
type AccountRepository struct {
	reader db.Reader
}

// NewAccountRespository creates a new AccountRepository
func NewAccountRepository(ctx context.Context, r db.Reader) (*AccountRepository, error) {
	const op = "account.NewAccountRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Reader")
	}

	return &AccountRepository{
		reader: r,
	}, nil
}

// GetTotalItems returns the total number of items in the accounts table.
func (ar *AccountRepository) GetTotalItems(ctx context.Context) (int, error) {
	const op = "account.(AccountRepository).GetTotalItems"
	rows, err := ar.reader.Query(ctx, estimateCountAccounts, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total accounts"))
	}
	var count int
	for rows.Next() {
		if err := ar.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total accounts"))
		}
	}
	return count, nil
}

// Now returns the current timestamp in the DB.
func (ar *AccountRepository) Now(ctx context.Context) (time.Time, error) {
	const op = "account.(AccountRepository).Now"
	rows, err := ar.reader.Query(ctx, "select current_timestamp", nil)
	if err != nil {
		return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
	}
	var now time.Time
	for rows.Next() {
		if err := ar.reader.ScanRows(ctx, rows, &now); err != nil {
			return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
		}
	}
	return now, nil
}

// ListDeletedIds lists the public IDs of any accounts deleted since the timestamp provided.
func (ar *AccountRepository) ListDeletedIds(ctx context.Context, since time.Time) ([]string, error) {
	const op = "account.(AccountRepository).ListDeletedIds"
	var deletedAccounts []*deletedAccount
	if err := ar.reader.SearchWhere(ctx, &deletedAccounts, "delete_time >= ?", []any{since}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted accounts"))
	}
	var accountIds []string
	for _, acct := range deletedAccounts {
		accountIds = append(accountIds, acct.PublicId)
	}
	return accountIds, nil
}

type deletedAccount struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedAccount) TableName() string {
	return "auth_account_deleted"
}
