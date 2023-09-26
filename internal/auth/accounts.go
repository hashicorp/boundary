// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// AccountRepository defines the interface expected
// to get the total number of accounts and deleted ids.
type AccountRepository interface {
	GetTotalAccounts(context.Context) (int, error)
	ListDeletedAccountIds(context.Context, time.Time, ...Option) ([]string, error)
}

// NewAccountService returns a new credential store service.
func NewAccountService(ctx context.Context, writer db.Writer, ldapRepo AccountRepository, oidcRepo AccountRepository, pwRepo AccountRepository) (*AccountService, error) {
	const op = "credential.NewAccountService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(ldapRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing ldap repo")
	case util.IsNil(oidcRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing oidc repo")
	case util.IsNil(pwRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password repo")
	}
	return &AccountService{
		repos:  []AccountRepository{ldapRepo, oidcRepo, pwRepo},
		writer: writer,
	}, nil
}

// AccountService coordinates calls to across different subtype repositories
// to gather information about all credential stores.
type AccountService struct {
	repos  []AccountRepository
	writer db.Writer
}

// GetTotalItems gets an estimate of the total number of credential stores across all types
func (s *AccountService) GetTotalItems(ctx context.Context) (int, error) {
	const op = "credential.(*AccountRepository).GetTotalItems"
	var totalNumAccounts int
	for _, repo := range s.repos {
		numAccounts, err := repo.GetTotalAccounts(ctx)
		if err != nil {
			return 0, errors.Wrap(ctx, err, op)
		}
		totalNumAccounts += numAccounts
	}
	return totalNumAccounts, nil
}

// ListDeletedIds lists all deleted credential store IDs across all types
func (s *AccountService) ListDeletedIds(ctx context.Context, since time.Time) ([]string, error) {
	const op = "credential.(*AccountRepository).ListDeletedIds"
	var deletedIds []string
	_, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		for _, repo := range s.repos {
			deletedAccountIds, err := repo.ListDeletedAccountIds(ctx, since, WithReaderWriter(r, w))
			if err != nil {
				return err
			}
			deletedIds = append(deletedIds, deletedAccountIds...)
		}
		// TODO: Get transaction timestamp too
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return deletedIds, nil
}

// Temporary - will be replaced once generic function is refactored
func (s *AccountService) Now(ctx context.Context) (time.Time, error) {
	return time.Now(), nil
}
