// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// StoreListQueryResult describes the result from the
// credential store list query used to list all credential
// store subtypes.
type StoreListQueryResult struct {
	// PublicId is a surrogate key suitable for use in a public API.
	PublicId string `gorm:"primary_key"`
	// The Project Id of the owning project and must be set.
	ProjectId string
	// Optional name of the credential store.
	Name string
	// Optional description of the credential store.
	Description string
	// Create time of the credential store.
	CreateTime *timestamp.Timestamp
	// Update time of the credential store.
	UpdateTime *timestamp.Timestamp
	// Version of the credential store.
	Version uint32
	// Optional delete time of the credential store.
	DeleteTime *timestamp.Timestamp
	// Optional Vault address of the credential store.
	VaultAddress string
	// Optional namespace of the credential store.
	Namespace string
	// Optional CA cert of the credential store.
	CaCert []byte
	// Optional TLS server name of the credential store.
	TlsServerName string
	// Optionally specifies whether to skip TLS verification of the credential store.
	TlsSkipVerify bool
	// Optional worker filter of the credential store.
	WorkerFilter string
	// Optional token HMAC of the credential store.
	TokenHmac []byte
	// Optional token status of the credential store.
	TokenStatus string
	// Optional client certificate of the credential store.
	ClientCert []byte
	// Optional client cert key HMAC of the credential store.
	ClientCertKeyHmac []byte
	// The subtype of the credential store.
	Subtype string
}

func (s *StoreListQueryResult) toStore(ctx context.Context) (Store, error) {
	const op = "credential.(*StoreListQueryResult).toStore"

	newFn, ok := subtypeRegistry.newFunc(globals.Subtype(s.Subtype))
	if !ok {
		return nil, errors.New(ctx,
			errors.InvalidParameter,
			op,
			fmt.Sprintf("%s is an unknown credential store subtype of %s", s.PublicId, s.Subtype),
		)
	}

	return newFn(ctx, s)
}
