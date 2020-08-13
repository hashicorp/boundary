package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms/store"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
)

const (
	defaultExternalConfigTableName = "kms_external_config"
)

type ExternalConfig struct {
	*store.ExternalConfig
	tableName string `gorm:"-"`
}

// NewExternalConfig creates a new in memory external config.  ScopeId must be
// for a global or org scope, but the scope type validation will be deferred
// until the in memory external config is written to the database.  No options
// are currently supported.
func NewExternalConfig(scopeId string, confType KmsType, config string, opt ...Option) (*ExternalConfig, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new external config: missing scope id %w", db.ErrInvalidParameter)
	}
	if config == "" {
		return nil, fmt.Errorf("new external config: missing conf %w", db.ErrInvalidParameter)
	}
	c := &ExternalConfig{
		ExternalConfig: &store.ExternalConfig{
			ScopeId: scopeId,
			Type:    confType.String(),
			Config:  config,
		},
	}
	return c, nil
}

func allocExternalConfig() ExternalConfig {
	return ExternalConfig{
		ExternalConfig: &store.ExternalConfig{},
	}
}

// Clone creates a clone of the ExternalConfig
func (c *ExternalConfig) Clone() interface{} {
	cp := proto.Clone(c.ExternalConfig)
	return &ExternalConfig{
		ExternalConfig: cp.(*store.ExternalConfig),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the external config
// before it's written.
func (c *ExternalConfig) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if c.PrivateId == "" {
		return fmt.Errorf("external config vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if c.Type == "" {
			return fmt.Errorf("external config vet for write: missing type: %w", db.ErrInvalidParameter)
		}
		if c.CtConfig == nil { // check the ciphertext since that's the config going to the db.
			return fmt.Errorf("external config vet for write: missing config: %w", db.ErrInvalidParameter)
		}
		if c.ScopeId == "" {
			return fmt.Errorf("external config vet for write: missing scope id: %w", db.ErrInvalidParameter)
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (c *ExternalConfig) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultExternalConfigTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (c *ExternalConfig) SetTableName(n string) {
	c.tableName = n
}

func (c *ExternalConfig) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PrivateId},
		"resource-type":      []string{"external kms config"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{c.ScopeId},
	}
	return metadata
}

func (c *ExternalConfig) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.ExternalConfig directly
	if err := structwrapping.WrapStruct(ctx, cipher, c.ExternalConfig, nil); err != nil {
		return fmt.Errorf("error encrypting external config: %w", err)
	}
	return nil
}

func (c *ExternalConfig) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.ExternalConfig directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.ExternalConfig, nil); err != nil {
		return fmt.Errorf("error decrypting external config: %w", err)
	}
	return nil
}
