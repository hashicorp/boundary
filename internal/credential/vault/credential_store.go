// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// A CredentialStore contains credential libraries. It is owned by a project.
type CredentialStore struct {
	*store.CredentialStore
	tableName string `gorm:"-"`

	clientCert  *ClientCertificate `gorm:"-"`
	inputToken  TokenSecret        `gorm:"-"`
	outputToken *Token             `gorm:"-"`

	privateClientCert *ClientCertificate `gorm:"-"`
	privateToken      *Token             `gorm:"-"`
}

// NewCredentialStore creates a new in memory CredentialStore for a Vault
// server at vaultAddress assigned to projectId. Name, description, CA cert,
// client cert, namespace, TLS server name, worker filter, and TLS skip verify are the
// only valid options. All other options are ignored.
func NewCredentialStore(projectId string, vaultAddress string, token TokenSecret, opt ...Option) (*CredentialStore, error) {
	opts := getOpts(opt...)
	cs := &CredentialStore{
		inputToken: token,
		clientCert: opts.withClientCert,
		CredentialStore: &store.CredentialStore{
			ProjectId:     projectId,
			Name:          opts.withName,
			Description:   opts.withDescription,
			VaultAddress:  vaultAddress,
			CaCert:        opts.withCACert,
			Namespace:     opts.withNamespace,
			TlsServerName: opts.withTlsServerName,
			TlsSkipVerify: opts.withTlsSkipVerify,
			WorkerFilter:  opts.withWorkerFilter,
		},
	}
	return cs, nil
}

func allocCredentialStore() *CredentialStore {
	return &CredentialStore{
		CredentialStore: &store.CredentialStore{},
	}
}

func (cs *CredentialStore) clone() *CredentialStore {
	tokenCopy := make(TokenSecret, len(cs.inputToken))
	copy(tokenCopy, cs.inputToken)
	var clientCertCopy *ClientCertificate
	if cs.clientCert != nil {
		clientCertCopy = cs.clientCert.clone()
	}
	cp := proto.Clone(cs.CredentialStore)
	return &CredentialStore{
		inputToken:      tokenCopy,
		clientCert:      clientCertCopy,
		CredentialStore: cp.(*store.CredentialStore),
	}
}

// applyUpdate returns a new CredentialStore with the new values applied to
// this based on the passed in fieldMaskPaths.
func (cs *CredentialStore) applyUpdate(new *CredentialStore, fieldMaskPaths []string) *CredentialStore {
	cp := cs.clone()
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
			cp.Name = new.Name
		case strings.EqualFold(descriptionField, f):
			cp.Description = new.Description
		case strings.EqualFold(certificateField, f):
			if new.clientCert == nil {
				cp.clientCert = nil
				continue
			}
			if cp.clientCert == nil {
				cp.clientCert = allocClientCertificate()
			}
			cp.clientCert.Certificate = new.clientCert.GetCertificate()
			cp.clientCert.StoreId = cs.GetPublicId()
		case strings.EqualFold(certificateKeyField, f):
			if new.clientCert == nil {
				cp.clientCert = nil
				continue
			}
			if cp.clientCert == nil {
				cp.clientCert = allocClientCertificate()
			}
			cp.clientCert.CertificateKey = new.clientCert.GetCertificateKey()
			cp.clientCert.StoreId = cs.GetPublicId()
		case strings.EqualFold(vaultAddressField, f):
			cp.VaultAddress = new.VaultAddress
		case strings.EqualFold(namespaceField, f):
			cp.Namespace = new.Namespace
		case strings.EqualFold(caCertField, f):
			cp.CaCert = new.CaCert
		case strings.EqualFold(tlsServerNameField, f):
			cp.TlsServerName = new.TlsServerName
		case strings.EqualFold(tlsSkipVerifyField, f):
			cp.TlsSkipVerify = new.TlsSkipVerify
		case strings.EqualFold(tokenField, f):
			cp.inputToken = new.inputToken
		case strings.EqualFold(workerFilterField, f):
			cp.WorkerFilter = new.WorkerFilter
		}
	}
	return cp
}

// TableName returns the table name.
func (cs *CredentialStore) TableName() string {
	if cs.tableName != "" {
		return cs.tableName
	}
	return "credential_vault_store"
}

// SetTableName sets the table name.
func (cs *CredentialStore) SetTableName(n string) {
	cs.tableName = n
}

// GetResourceType returns the resource type of the CredentialStore
func (cs *CredentialStore) GetResourceType() resource.Type {
	return resource.CredentialStore
}

func (cs *CredentialStore) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{cs.PublicId},
		"resource-type":      []string{"credential-vault-store"},
		"op-type":            []string{op.String()},
	}
	if cs.ProjectId != "" {
		metadata["project-id"] = []string{cs.ProjectId}
	}
	return metadata
}

func (cs *CredentialStore) oplogMessage(opType db.OpType) *oplog.Message {
	msg := oplog.Message{
		Message:  cs.clone(),
		TypeName: cs.TableName(),
	}
	switch opType {
	case db.CreateOp:
		msg.OpType = oplog.OpType_OP_TYPE_CREATE
	case db.UpdateOp:
		msg.OpType = oplog.OpType_OP_TYPE_UPDATE
	case db.DeleteOp:
		msg.OpType = oplog.OpType_OP_TYPE_DELETE
	}
	return &msg
}

// Token returns the current vault token if available.
func (cs *CredentialStore) Token() *Token {
	return cs.outputToken
}

// ClientCertificate returns the client certificate if available.
func (cs *CredentialStore) ClientCertificate() *ClientCertificate {
	return cs.clientCert
}

func (cs *CredentialStore) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(CredentialStore).client"
	clientConfig := &clientConfig{
		Addr:          cs.VaultAddress,
		Token:         cs.inputToken,
		CaCert:        cs.CaCert,
		TlsServerName: cs.TlsServerName,
		TlsSkipVerify: cs.TlsSkipVerify,
		Namespace:     cs.Namespace,
	}
	if cs.clientCert != nil {
		clientConfig.ClientCert = cs.clientCert.GetCertificate()
		clientConfig.ClientKey = cs.clientCert.GetCertificateKey()
	}

	c, err := vaultClientFactoryFn(ctx, clientConfig, WithWorkerFilter(cs.WorkerFilter))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return c, nil
}

func (cs *CredentialStore) softDeleteQuery() (query string, queryValues []any) {
	query = softDeleteStoreQuery
	queryValues = []any{
		cs.PublicId,
	}
	return query, queryValues
}
