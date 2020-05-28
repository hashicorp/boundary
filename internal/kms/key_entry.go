package kms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

// KeyEntry defines watchtower key entry
type KeyEntry struct {
	*store.KeyEntry
	tableName string `gorm:"-"`
}

var _ db.VetForWriter = (*KeyEntry)(nil)

// NewKeyEntry creates a new in memory key entry and allows options:
// WithParentKeyId - to specify the entry's parent key id
func NewKeyEntry(organizationPublicId, keyId string, key []byte, opt ...Option) (*KeyEntry, error) {
	opts := getOpts(opt...)

	if organizationPublicId == "" {
		return nil, fmt.Errorf("new key entry: missing organization id %w", db.ErrNilParameter)
	}
	if keyId == "" {
		return nil, fmt.Errorf("new key entry: missing key id %w", db.ErrNilParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("new key entry: missing key %w", db.ErrNilParameter)
	}
	u := &KeyEntry{
		KeyEntry: &store.KeyEntry{
			ParentKeyId: opts.withParentKeyId,
			KeyId:       keyId,
			Key:         key,
			ScopeId:     organizationPublicId,
		},
	}
	return u, nil
}

func allocKeyEntry() KeyEntry {
	return KeyEntry{
		KeyEntry: &store.KeyEntry{},
	}
}

// Clone creates a clone of the KeyEntry
func (k *KeyEntry) Clone() *KeyEntry {
	cp := proto.Clone(k.KeyEntry)
	return &KeyEntry{
		KeyEntry: cp.(*store.KeyEntry),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key entry
// before it's written.
func (k *KeyEntry) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.KeyId == "" {
		return fmt.Errorf("key entry vet for write: missing key id: %w", db.ErrNilParameter)
	}
	if err := k.validateScopeForWrite(ctx, r, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (k *KeyEntry) validScopeTypes() []iam.ScopeType {
	return []iam.ScopeType{iam.OrganizationScope}
}

// validateScopeForWrite will validate that the scope is okay for db write operations
func (k *KeyEntry) validateScopeForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	opts := db.GetOpts(opt...)

	if opType == db.CreateOp {
		if k.ScopeId == "" {
			return errors.New("error scope id not set for key entry write")
		}
		ps, err := k.GetScope(ctx, r)
		if err != nil {
			if errors.Is(err, db.ErrRecordNotFound) {
				return errors.New("scope is not found")
			}
			return err
		}
		validScopeType := false
		for _, t := range k.validScopeTypes() {
			if ps.Type == t.String() {
				validScopeType = true
			}
		}
		if !validScopeType {
			return fmt.Errorf("%s not a valid scope type for this resource", ps.Type)
		}

	}
	if opType == db.UpdateOp && k.ScopeId != "" {
		switch len(opts.WithFieldMaskPaths) {
		case 0:
			return errors.New("not allowed to change a key entry's scope")
		default:
			for _, mask := range opts.WithFieldMaskPaths {
				if strings.EqualFold(mask, "ScopeId") {
					return errors.New("not allowed to change a key entry's scope")
				}
			}
		}
	}
	return nil
}

// GetScope returns the scope for the key entry
func (k *KeyEntry) GetScope(ctx context.Context, r db.Reader) (*iam.Scope, error) {
	if r == nil {
		return nil, errors.New("error reader is nil for for getting scope")
	}
	if k.KeyId == "" {
		return nil, fmt.Errorf("error key id is not set for getting scope: %w", db.ErrInvalidParameter)
	}
	if k.ScopeId == "" {
		// try to retrieve it from db with it's scope id
		foundEntry := allocKeyEntry()
		foundEntry.KeyId = k.KeyId
		if err := r.LookupWhere(ctx, &foundEntry, "key_id = ?", foundEntry.KeyId); err != nil {
			return nil, fmt.Errorf("unable to get resource by key id %s: %w", foundEntry.KeyId, err)
		}
		// if it's still not set after getting it from the db...
		if foundEntry.ScopeId == "" {
			return nil, errors.New("error scope is unset for getting scope")
		}
		k.ScopeId = foundEntry.ScopeId
	}
	var s iam.Scope
	if err := r.LookupWhere(ctx, &s, "public_id = ?", k.ScopeId); err != nil {
		return nil, err
	}
	return &s, nil
}

// TableName returns the tablename to override the default gorm table name
func (k *KeyEntry) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return "kms_key_entry"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (k *KeyEntry) SetTableName(n string) {
	if n != "" {
		k.tableName = n
	}
}
