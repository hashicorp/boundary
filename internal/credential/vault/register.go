// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
)

func init() {
	credential.RegisterStoreSubtype("vault", &credentialHooks{})
}

type credentialHooks struct{}

// NewStore creates a new Vault credential store from the store union
func (credentialHooks) NewStore(ctx context.Context, storeUnion *credential.StoreUnion) (credential.Store, error) {
	s := allocCredentialStore()
	s.PublicId = storeUnion.PublicId
	s.ProjectId = storeUnion.ProjectId
	s.CreateTime = storeUnion.CreateTime
	s.UpdateTime = storeUnion.UpdateTime
	s.Name = storeUnion.Name
	s.Description = storeUnion.Description
	s.ProjectId = storeUnion.ProjectId
	s.Version = storeUnion.Version
	s.VaultAddress = storeUnion.VaultAddress
	s.Namespace = storeUnion.Namespace
	s.CaCert = storeUnion.CaCert
	s.TlsServerName = storeUnion.TlsServerName
	s.TlsSkipVerify = storeUnion.TlsSkipVerify
	s.WorkerFilter = storeUnion.WorkerFilter

	return s, nil
}
