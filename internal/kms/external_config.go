package kms

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms/store"
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
// until the in memory external config is written to the database.  The config
// parmater must be valid json.  No options are currently supported.
func NewExternalConfig(scopeId string, confType KmsType, config string, opt ...Option) (*ExternalConfig, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new external config: missing scope id %w", db.ErrInvalidParameter)
	}
	if config == "" {
		return nil, fmt.Errorf("new external config: missing conf %w", db.ErrInvalidParameter)
	}
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("new external config: %w", err)
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

func validateConfig(str string) error {
	var js json.RawMessage
	if json.Unmarshal([]byte(str), &js) != nil {
		return fmt.Errorf("config is not valid json: %w", db.ErrInvalidParameter)
	}
	return nil
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
	if c.Type == "" {
		return fmt.Errorf("external config vet for write: missing type: %w", db.ErrInvalidParameter)
	}
	if c.Config == "" {
		return fmt.Errorf("external config vet for write: missing config: %w", db.ErrInvalidParameter)
	}
	if err := validateConfig(c.Config); err != nil {
		return fmt.Errorf("external config vet for write: %w", err)
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
