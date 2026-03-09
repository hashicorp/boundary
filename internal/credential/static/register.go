// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
)

func init() {
	credential.RegisterStoreSubtype("static", &credentialHooks{})
}

type credentialHooks struct{}

// NewStore creates a new static credential store from the result
func (credentialHooks) NewStore(ctx context.Context, result *credential.StoreListQueryResult) (credential.Store, error) {
	s := allocCredentialStore()
	s.PublicId = result.PublicId
	s.ProjectId = result.ProjectId
	s.CreateTime = result.CreateTime
	s.UpdateTime = result.UpdateTime
	s.Name = result.Name
	s.Description = result.Description
	s.ProjectId = result.ProjectId
	s.Version = result.Version

	return s, nil
}
