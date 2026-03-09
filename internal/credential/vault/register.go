// Copyright IBM Corp. 2020, 2025
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

// NewStore creates a new Vault credential store from the result
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
	s.VaultAddress = result.VaultAddress
	s.Namespace = result.Namespace
	s.CaCert = result.CaCert
	s.TlsServerName = result.TlsServerName
	s.TlsSkipVerify = result.TlsSkipVerify
	s.WorkerFilter = result.WorkerFilter

	s.outputToken = allocToken()
	s.outputToken.Status = result.TokenStatus
	s.outputToken.TokenHmac = result.TokenHmac

	if len(result.ClientCert) > 0 {
		s.clientCert = allocClientCertificate()
		s.clientCert.Certificate = result.ClientCert
		s.clientCert.CertificateKeyHmac = result.ClientCertKeyHmac
	}

	return s, nil
}
