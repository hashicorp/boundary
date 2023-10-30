// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// List lists both generic and SSH credential libraries.
// Supports the following options:
//   - credential.WithLimit
//   - credential.WithStartPageAfterItem
func (s *LibraryService) List(ctx context.Context, credentialStoreId string, opts ...credential.Option) ([]credential.Library, error) {
	const op = "vault.(*LibraryService).List"
	opt, err := credential.GetOpts(opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	genericLibs, err := s.repo.listCredentialLibraries(ctx, credentialStoreId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	sshCertLibs, err := s.repo.listSSHCertificateCredentialLibraries(ctx, credentialStoreId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	libs := append(genericLibs, sshCertLibs...)
	slices.SortFunc(libs, func(i, j credential.Library) int {
		return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
	})
	if opt.WithLimit == -1 {
		// No limit, no truncation
		return libs, nil
	}
	limit := s.repo.defaultLimit
	if opt.WithLimit != 0 {
		limit = opt.WithLimit
	}
	// Truncate slice to at most limit number of elements
	if len(libs) > limit {
		libs = libs[:limit]
	}
	return libs, nil
}

// EstimatedCount estimates the total count of Vault credential libraries, both generic and SSH.
func (s *LibraryService) EstimatedCount(ctx context.Context) (int, error) {
	const op = "vault.(*LibraryService).EstimatedCount"
	numGenericLibs, err := s.repo.estimatedLibraryCount(ctx)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	numSSHCertLibs, err := s.repo.estimatedSSHCertificateLibraryCount(ctx)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	return numGenericLibs + numSSHCertLibs, nil
}

// ListDeletedIds lists the IDs of credential libraries deleted since the provided timestamp,
// both generic and SSH.
func (s *LibraryService) ListDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "vault.(*LibraryService).ListDeletedIds"
	// Request and combine deleted ids from the DB for generic and ssh cert libraries.
	// This statement here is the reason we need a struct for this. We need all the
	// deleted libraries to be collated in a single transaction with a single
	// transaction timestamp. This requires access to a db Reader, which isn't available
	// to the handlers and can't be passed into this method. Therefore, a struct,
	// constructed in the controller, is necessary.
	var deletedIds []string
	var transactionTimestamp time.Time
	if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		deletedGenericIds, err := s.repo.listDeletedLibraryIds(ctx, since, credential.WithReaderWriter(r, w))
		if err != nil {
			return err
		}
		deletedSSHCertIds, err := s.repo.listDeletedSSHCertificateLibraryIds(ctx, since, credential.WithReaderWriter(r, w))
		if err != nil {
			return err
		}
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return err
		}
		deletedIds = append(deletedGenericIds, deletedSSHCertIds...)
		return nil
	}); err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}
	return deletedIds, transactionTimestamp, nil
}
