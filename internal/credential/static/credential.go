// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// listCredentialResult represents the result of the
// list queries used to list all credentials.
type listCredentialResult struct {
	PublicId    string
	StoreId     string
	ProjectId   string
	Name        string
	Description string
	Username    string
	Domain      string
	KeyId       string
	Hmac1       string
	Hmac2       string
	CreateTime  *timestamp.Timestamp
	UpdateTime  *timestamp.Timestamp
	Version     int
	Type        string
}

func (c *listCredentialResult) toCredential(ctx context.Context) (credential.Static, error) {
	const op = "vault.(*listCredentialLibraryResult).toCredential"
	switch c.Type {
	case "json":
		cred := &JsonCredential{
			JsonCredential: &store.JsonCredential{
				PublicId:    c.PublicId,
				StoreId:     c.StoreId,
				Name:        c.Name,
				Description: c.Description,
				CreateTime:  c.CreateTime,
				UpdateTime:  c.UpdateTime,
				Version:     uint32(c.Version),
				KeyId:       c.KeyId,
			},
		}
		// Assign byte slices only if the string isn't empty
		if c.Hmac1 != "" {
			cred.ObjectHmac = []byte(c.Hmac1)
		}
		return cred, nil
	case "upw":
		cred := &UsernamePasswordCredential{
			UsernamePasswordCredential: &store.UsernamePasswordCredential{
				PublicId:    c.PublicId,
				StoreId:     c.StoreId,
				Name:        c.Name,
				Description: c.Description,
				CreateTime:  c.CreateTime,
				UpdateTime:  c.UpdateTime,
				Version:     uint32(c.Version),
				Username:    c.Username,
				KeyId:       c.KeyId,
			},
		}
		// Assign byte slices only if the string isn't empty
		if c.Hmac1 != "" {
			cred.PasswordHmac = []byte(c.Hmac1)
		}
		return cred, nil
	case "upd":
		cred := &UsernamePasswordDomainCredential{
			UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
				PublicId:    c.PublicId,
				StoreId:     c.StoreId,
				Name:        c.Name,
				Description: c.Description,
				CreateTime:  c.CreateTime,
				UpdateTime:  c.UpdateTime,
				Version:     uint32(c.Version),
				Username:    c.Username,
				Domain:      c.Domain,
				KeyId:       c.KeyId,
			},
		}
		// Assign byte slices only if the string isn't empty
		if c.Hmac1 != "" {
			cred.PasswordHmac = []byte(c.Hmac1)
		}
		return cred, nil
	case "p":
		cred := &PasswordCredential{
			PasswordCredential: &store.PasswordCredential{
				PublicId:    c.PublicId,
				StoreId:     c.StoreId,
				Name:        c.Name,
				Description: c.Description,
				CreateTime:  c.CreateTime,
				UpdateTime:  c.UpdateTime,
				Version:     uint32(c.Version),
				KeyId:       c.KeyId,
			},
		}
		// Assign byte slices only if the string isn't empty
		if c.Hmac1 != "" {
			cred.PasswordHmac = []byte(c.Hmac1)
		}
		return cred, nil
	case "ssh":
		cred := &SshPrivateKeyCredential{
			SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
				PublicId:    c.PublicId,
				StoreId:     c.StoreId,
				Name:        c.Name,
				Description: c.Description,
				CreateTime:  c.CreateTime,
				UpdateTime:  c.UpdateTime,
				Version:     uint32(c.Version),
				Username:    c.Username,
				KeyId:       c.KeyId,
			},
		}
		// Assign byte slices only if the string isn't empty
		if c.Hmac1 != "" {
			cred.PrivateKeyHmac = []byte(c.Hmac1)
		}
		if c.Hmac2 != "" {
			cred.PrivateKeyPassphraseHmac = []byte(c.Hmac2)
		}
		return cred, nil
	default:
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unexpected static credential type %s returned", c.Type))
	}
}
