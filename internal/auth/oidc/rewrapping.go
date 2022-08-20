package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn(defaultAuthMethodTableName, getAuthMethodRewrapFn(defaultAccountTableName))
}

var allAuthMethodFields = []string{
	OperationalStateField,
	DisableDiscoveredConfigValidationField,
	VersionField,
	NameField,
	DescriptionField,
	FilterField,
	IssuerField,
	ClientIdField,
	ClientSecretField,
	CtClientSecretField,
	ClientSecretHmacField,
	MaxAgeField,
	SigningAlgsField,
	ApiUrlField,
	AudClaimsField,
	CertificatesField,
	ClaimsScopesField,
	AccountClaimMapsField,
	TokenClaimsField,
	UserinfoClaimsField,
}

func getAuthMethodRewrapFn(authMethodTableName string) kms.RewrapFn {
	return func(ctx context.Context, dataKeyId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
		repo, err := NewRepository(ctx, reader, writer, kmsRepo)
		if err != nil {
			return err
		}

		rows, err := repo.reader.Query(ctx, fmt.Sprintf(`select distinct scope_id from %q where key_id=?`, authMethodTableName), []interface{}{dataKeyId})
		if err != nil {
			return err
		}
		var scopeIds []string
		for rows.Next() {
			var scopeId string
			if err := rows.Scan(&scopeId); err != nil {
				_ = rows.Close()
				return err
			}
			scopeIds = append(scopeIds, scopeId)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, scopeId := range scopeIds {
			var authMethods []*AuthMethod
			if err := repo.reader.SearchWhere(ctx, &authMethods, "scope_id=? and key_id=?", []interface{}{scopeId, dataKeyId}, db.WithLimit(-1)); err != nil {
				return err
			}
			wrapper, err := repo.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
			if err != nil {
				return err
			}
			for _, am := range authMethods {
				if err := am.decrypt(ctx, wrapper); err != nil {
					return err
				}
				if err := am.encrypt(ctx, wrapper); err != nil {
					return err
				}
				if _, err := repo.writer.Update(ctx, am, allAuthMethodFields, nil); err != nil {
					return err
				}
				// TODO: Should we add a sleep here to pace the DB updates?
			}
			// TODO: Should we sleep here to pace the DB load?
		}
		return nil
	}
}
