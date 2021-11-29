package plugin

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// HostCatalogSecret contains the encrypted secret for a host catalog.
// It is owned by a HostCatalog.
type HostCatalogSecret struct {
	*store.HostCatalogSecret
	tableName string `gorm:"-"`
}

// newHostCatalogSecret creates an in memory host catalog secret.
// All options are ignored.
//
// The TTL indicates the refresh time in from the current time in
// seconds. A negative value indicates never refresh.
func newHostCatalogSecret(ctx context.Context, catalogId string, ttl *wrapperspb.UInt32Value, secret *structpb.Struct, _ ...Option) (*HostCatalogSecret, error) {
	const op = "plugin.newHostCatlogSecret"
	var refreshAtTime *timestamp.Timestamp
	if ttl != nil {
		refreshAtTime = timestamp.New(time.Now().UTC().Add(time.Second * time.Duration(ttl.GetValue())))
	}

	hcs := &HostCatalogSecret{
		HostCatalogSecret: &store.HostCatalogSecret{
			CatalogId:     catalogId,
			RefreshAtTime: refreshAtTime,
		},
	}

	if secret != nil {
		attrs, err := proto.Marshal(secret)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
		}
		hcs.Secret = attrs
	}
	return hcs, nil
}

func allocHostCatalogSecret() *HostCatalogSecret {
	return &HostCatalogSecret{
		HostCatalogSecret: &store.HostCatalogSecret{},
	}
}

func (c *HostCatalogSecret) clone() *HostCatalogSecret {
	cp := proto.Clone(c.HostCatalogSecret)
	return &HostCatalogSecret{
		HostCatalogSecret: cp.(*store.HostCatalogSecret),
	}
}

// TableName returns the table name for the host catalog.
func (c *HostCatalogSecret) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "host_plugin_catalog_secret"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *HostCatalogSecret) SetTableName(n string) {
	c.tableName = n
}

func (c *HostCatalogSecret) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "plugin.(HostCatalogSecret).encrypt"
	if len(c.Secret) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no attributes defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.HostCatalogSecret, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	c.KeyId = cipher.KeyID()
	c.Secret = nil
	return nil
}

func (c *HostCatalogSecret) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "plugin.(HostCatalogSecret).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.HostCatalogSecret, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	c.CtSecret = nil
	return nil
}

func (c *HostCatalogSecret) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-catalog-id": []string{c.CatalogId},
		"op-type":             []string{op.String()},
	}
	return metadata
}
