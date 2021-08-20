package plugin

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
)

type HostCatalogSecret struct {
	*store.HostCatalogSecret
	tableName string `gorm:"-"`
}

// newHostCatalogSecret creates an in memory host catalog secret.
// All options are ignored.
func newHostCatalogSecret(ctx context.Context, catalogId string, attributes map[string]interface{}, _ ...Option) (*HostCatalogSecret, error) {
	const op = "plugin.newHostCatlogSecret"
	hcs := &HostCatalogSecret{
		HostCatalogSecret: &store.HostCatalogSecret{
			CatalogId: catalogId,
		},
	}

	if attributes != nil {
		attrs, err := json.Marshal(attributes)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
		}
		hcs.Secret = attrs
	}
	return hcs, nil
}

// TableName returns the table name for the host catalog.
func (c *HostCatalogSecret) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "plugin_host_catalog_secret"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *HostCatalogSecret) SetTableName(n string) {
	c.tableName = n
}

func (c *HostCatalogSecret) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(HostCatalogSecret).encrypt"
	if len(c.Secret) == 0 {
		errors.New(ctx, errors.InvalidParameter, op, "no attributes defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.HostCatalogSecret, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	c.KeyId = cipher.KeyID()
	c.Secret = nil
	return nil
}

func (c *HostCatalogSecret) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(HostCatalogSecret).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.HostCatalogSecret, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	c.CtSecret = nil
	return nil
}

func (c *HostCatalogSecret) insertQuery() (query string, queryValues []interface{}) {
	query = upsertHostCatalogSecretQuery
	queryValues = []interface{}{
		c.CatalogId,
		c.CtSecret,
		c.KeyId,
	}
	return
}

func (c *HostCatalogSecret) deleteQuery() (query string, queryValues []interface{}) {
	query = deleteHostCatalogSecretQuery
	queryValues = []interface{}{
		c.CatalogId,
	}
	return
}
