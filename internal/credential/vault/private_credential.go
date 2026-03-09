// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

type privateCredential struct {
	PublicId             string `gorm:"primary_key"`
	LibraryId            string
	SessionId            string
	CreateTime           *timestamp.Timestamp
	UpdateTime           *timestamp.Timestamp
	Version              uint32
	ExternalId           string
	LastRenewalTime      *timestamp.Timestamp
	ExpirationTime       *timestamp.Timestamp
	IsRenewable          bool
	Status               string
	RenewalTime          *timestamp.Timestamp
	TokenHmac            []byte
	Token                TokenSecret
	CtToken              []byte
	TokenCreateTime      *timestamp.Timestamp
	TokenUpdateTime      *timestamp.Timestamp
	TokenLastRenewalTime *timestamp.Timestamp
	TokenExpirationTime  *timestamp.Timestamp
	TokenKeyId           string
	TokenStatus          string
	ProjectId            string
	VaultAddress         string
	Namespace            string
	CaCert               []byte
	TlsServerName        string
	TlsSkipVerify        bool
	WorkerFilter         string
	ClientCert           []byte
	ClientKey            KeySecret
	CtClientKey          []byte
	ClientKeyHmac        []byte
	ClientKeyId          string
	SessionCorrelationId string
}

func (pc *privateCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(privateCredential).decrypt"
	if pc.CtToken != nil {
		type ptk struct {
			Token   []byte `wrapping:"pt,token_data"`
			CtToken []byte `wrapping:"ct,token_data"`
		}
		ptkv := &ptk{
			CtToken: pc.CtToken,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, ptkv, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("token"))
		}
		pc.Token = ptkv.Token
	}

	if pc.CtClientKey != nil && pc.ClientCert != nil {
		type pck struct {
			Key   []byte `wrapping:"pt,key_data"`
			CtKey []byte `wrapping:"ct,key_data"`
		}
		pckv := &pck{
			CtKey: pc.CtClientKey,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, pckv, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("client certificate"))
		}
		pc.ClientKey = pckv.Key
	}
	return nil
}

func (pc *privateCredential) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(privateCredential).client"
	clientConfig := &clientConfig{
		Addr:          pc.VaultAddress,
		Token:         pc.Token,
		CaCert:        pc.CaCert,
		TlsServerName: pc.TlsServerName,
		TlsSkipVerify: pc.TlsSkipVerify,
		Namespace:     pc.Namespace,
	}

	if pc.ClientKey != nil {
		clientConfig.ClientCert = pc.ClientCert
		clientConfig.ClientKey = pc.ClientKey
	}

	client, err := vaultClientFactoryFn(ctx, clientConfig, WithWorkerFilter(pc.WorkerFilter))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

func (pc *privateCredential) toCredential() *Credential {
	return &Credential{
		Credential: &store.Credential{
			PublicId:        pc.PublicId,
			LibraryId:       pc.LibraryId,
			SessionId:       pc.SessionId,
			TokenHmac:       append(pc.TokenHmac[:0:0], pc.TokenHmac...),
			CreateTime:      proto.Clone(pc.CreateTime).(*timestamp.Timestamp),
			UpdateTime:      proto.Clone(pc.UpdateTime).(*timestamp.Timestamp),
			Version:         pc.Version,
			ExternalId:      pc.ExternalId,
			LastRenewalTime: proto.Clone(pc.LastRenewalTime).(*timestamp.Timestamp),
			ExpirationTime:  proto.Clone(pc.ExpirationTime).(*timestamp.Timestamp),
			IsRenewable:     pc.IsRenewable,
			Status:          pc.Status,
		},
	}
}

// GetPublicId returns the public id.
func (pc *privateCredential) GetPublicId() string {
	return pc.PublicId
}

// TableName returns the table name for gorm.
func (pc *privateCredential) TableName() string {
	return "credential_vault_credential_private"
}
