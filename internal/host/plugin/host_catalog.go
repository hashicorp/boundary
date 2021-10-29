// Package plugin provides a plugin host catalog, and plugin host set resource
// which are used to interact with a host plugin as well as a repository to
// perform CRUDL and custom actions on these resource types.
package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"
)

// A HostCatalog contains plugin host sets. It is owned by
// a scope.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`

	Attributes *structpb.Struct `gorm:"-"`
	Secrets    *structpb.Struct `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to a scopeId
// and pluginId. Name and description are the only valid options. All other
// options are ignored.
func NewHostCatalog(ctx context.Context, scopeId, pluginId string, opt ...Option) *HostCatalog {
	opts := getOpts(opt...)

	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			ScopeId:     scopeId,
			PluginId:    pluginId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Attributes:  make([]byte, 0),
		},
		Attributes: opts.withAttributes,
		Secrets:    opts.withSecrets,
	}
	return hc
}

func allocHostCatalog() *HostCatalog {
	return &HostCatalog{
		HostCatalog: &store.HostCatalog{},
	}
}

// clone provides a deep copy of the HostCatalog with the exception of the
// secret.  The secret shallow copied.
func (c *HostCatalog) clone() *HostCatalog {
	cp := proto.Clone(c.HostCatalog)
	newAttributes := proto.Clone(c.Attributes)
	newSecret := proto.Clone(c.Secrets)

	hc := &HostCatalog{
		HostCatalog: cp.(*store.HostCatalog),
		Attributes:  newAttributes.(*structpb.Struct),
		Secrets:     newSecret.(*structpb.Struct),
	}
	// proto.Clone will convert slices with length and capacity of 0 to nil.
	// Fix this since gorm treats empty slices differently than nil.
	if c.HostCatalog.Attributes != nil && len(c.HostCatalog.Attributes) == 0 && hc.HostCatalog.Attributes == nil {
		hc.HostCatalog.Attributes = []byte{}
	}
	return hc
}

// TableName returns the table name for the host catalog.
func (c *HostCatalog) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "host_plugin_catalog"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *HostCatalog) SetTableName(n string) {
	c.tableName = n
}

func (s *HostCatalog) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"plugin-host-catalog"},
		"op-type":            []string{op.String()},
	}
	if s.ScopeId != "" {
		metadata["scope-id"] = []string{s.ScopeId}
	}
	return metadata
}

// unmarshalAttributes marshals the attributes contained within the
// embedded store.HostCatalog wire format into the higher-level
// structpb.Struct Attribute field. It also sets the embedded store
// field to nil to prevent its direct use.
func (c *HostCatalog) unmarshalAttributes() error {
	if c.HostCatalog == nil {
		// no-op
		return nil
	}

	c.Attributes = new(structpb.Struct)
	if err := proto.Unmarshal(c.HostCatalog.Attributes, c.Attributes); err != nil {
		return err
	}

	c.HostCatalog.Attributes = nil
	return nil
}

// AfterFind implements callbacks.AfterFind for HostCatalog for
// transparent unmarshaling of the binary attributes field into the
// higher-level struct field.
func (c *HostCatalog) AfterFind(_ *gorm.DB) error {
	return c.unmarshalAttributes()
}

// marshalAttributes marshals the attributes contained within the
// higher-level Attributes field into the embedded wire-format
// Attributes field within the store data structure.
//
// Note that unlike unmarshalAttributes, it does *not* clear out the
// higher-level attributes field afterwards.
func (c *HostCatalog) marshalAttributes() error {
	if c.HostCatalog == nil {
		// no-op
		return nil
	}

	var b []byte
	if c.Attributes == nil {
		b = make([]byte, 0)
	} else {
		var err error
		b, err = proto.Marshal(c.Attributes)
		if err != nil {
			return err
		}
	}

	c.HostCatalog.Attributes = b
	return nil
}

// BeforeSave implements callbacks.BeforeSave for HostCatalog for
// transparent marshaling of the binary attributes field into the
// higher-level struct field.
func (c *HostCatalog) BeforeSave(tx *gorm.DB) error {
	// For consistency, update the underlying binary attributes field.
	if err := c.marshalAttributes(); err != nil {
		return err
	}

	// If we're updating the attributes field, we now also need to sync the
	// in-flight value with the newly marshaled field.
	if tx.Statement.Changed("Attributes") {
		tx.Statement.SetColumn("Attributes", c.getEmbeddedAttributes())
	}

	return nil
}

// AfterSave implements callbacks.AfterSave for HostCatalog to nil
// out the attributes field after saving the record to the database.
func (c *HostCatalog) AfterSave(_ *gorm.DB) error {
	if c.HostCatalog == nil {
		// no-op
		return nil
	}

	c.HostCatalog.Attributes = nil
	return nil
}

// GetAttributes overrides the field getter for the embedded []uint8
// attributes field, and returns the top-level *structpb.Struct
// instead.
func (c *HostCatalog) GetAttributes() *structpb.Struct {
	if c == nil {
		return nil
	}

	return c.Attributes
}

func (c *HostCatalog) getEmbeddedAttributes() []byte {
	if c == nil {
		return nil
	}

	return c.HostCatalog.GetAttributes()
}
