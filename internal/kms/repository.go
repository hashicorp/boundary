package kms

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/lib/pq"
)

// Repository is the kms database repository
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewRepository creates a new kms Repository
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (*Repository, error) {
	if r == nil {
		return nil, fmt.Errorf("new repository: db reader: %w", db.ErrNilParameter)
	}
	if w == nil {
		return nil, fmt.Errorf("new repository: db writer: %w", db.ErrNilParameter)
	}
	if wrapper == nil {
		return nil, fmt.Errorf("new repository: wrapper: %w", db.ErrNilParameter)
	}
	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// CreateKeyEntry will create a key entry in the repository and return the written entry
func (r *Repository) CreateKeyEntry(ctx context.Context, k *KeyEntry, opt ...Option) (*KeyEntry, error) {
	if k == nil {
		return nil, fmt.Errorf("create key entry: missing entry %w", db.ErrNilParameter)
	}
	c := k.Clone()

	metadata := newKeyEntryMetadata(c, oplog.OpType_OP_TYPE_CREATE)

	var returnedEntry *KeyEntry
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			returnedEntry = c.Clone()
			return w.Create(
				ctx,
				returnedEntry,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)
	if err != nil {
		if uniqueError(err) {
			return nil, fmt.Errorf("create: kms key entry: key entry %s already exists in organization %s", k.KeyId, k.ScopeId)
		}
		return nil, fmt.Errorf("create: kms key entry: %w for %s", err, k.KeyId)
	}
	return returnedEntry, err
}

// TODO (jlambert 5/2020) uniqueError should be removed in favor of
// db.IsUnique(err) once the function has been merged to master
func uniqueError(err error) bool {
	if err == nil {
		return false
	}

	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code.Name() == "unique_violation" {
			return true
		}
	}

	return false
}

func newKeyEntryMetadata(k *KeyEntry, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-key-id": []string{k.KeyId},
		"resource-type":   []string{"kms key entry"},
		"op-type":         []string{op.String()},
	}
	if k.ScopeId != "" {
		metadata["scope-id"] = []string{k.ScopeId}
	}
	return metadata
}

// UpdateKeyEntry will update a key entry in the repository and return the written entry.
// fieldMaskPaths is required.  Any field set to zero value in the field mask
// will be set to NULL in the db.
func (r *Repository) UpdateKeyEntry(ctx context.Context, k *KeyEntry, fieldMaskPaths []string, opt ...Option) (*KeyEntry, int, error) {
	if k == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: missing key entry %w", db.ErrNilParameter)
	}
	if k.KeyId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: missing key id %w", db.ErrNilParameter)
	}
	if len(fieldMaskPaths) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: missing field masks %w", db.ErrNilParameter)
	}
	if contains(fieldMaskPaths, "scopeid") {
		return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: scope not updatable %w", db.ErrInvalidParameter)
	}
	if contains(fieldMaskPaths, "keyid") {
		return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: key id not updatable %w", db.ErrInvalidParameter)
	}
	var dbMask, nullFields []string
	dbMask, nullFields = buildUpdatePaths(
		map[string]interface{}{
			"key": k.Key,
		},
		fieldMaskPaths,
	)
	// nada to update, so reload key entry from db and return it
	if len(dbMask) == 0 && len(nullFields) == 0 {
		foundEntry := allocKeyEntry()
		if err := r.reader.LookupWhere(ctx, &foundEntry, "key_id = ?", k.KeyId); err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: failed for key id %s: %w", k.KeyId, err)
		}
		return &foundEntry, db.NoRowsAffected, nil
	}
	updatedEntry := k.Clone()
	// TODO (jimlambrt 5/2020) - need to send nullFields, once it's supported in
	// master
	// updatedEntry, rowsUpdated, err := r.writer.Update(ctx, clone, dbMask,
	// nullFields)
	metadata := newKeyEntryMetadata(updatedEntry, oplog.OpType_OP_TYPE_UPDATE)

	var rowsUpdated int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			updatedEntry = updatedEntry.Clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				updatedEntry,
				fieldMaskPaths,
				// nullFields,
				db.WithOplog(r.wrapper, metadata),
			)
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 resource would have been updated ")
			}
			return err
		},
	)
	if err != nil {
		if uniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: key entry %s already exists in organization %s", k.KeyId, k.ScopeId)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update kms key entry: %w for %s", err, k.KeyId)
	}
	return updatedEntry, rowsUpdated, err
}
func contains(ss []string, t string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}
func isZero(i interface{}) bool {
	return i == nil || reflect.DeepEqual(i, reflect.Zero(reflect.TypeOf(i)).Interface())
}

func buildUpdatePaths(fieldValues map[string]interface{}, fieldMask []string) (masks []string, nulls []string) {
	for f, v := range fieldValues {
		if !contains(fieldMask, f) {
			continue
		}
		switch {
		case isZero(v):
			nulls = append(nulls, f)
		default:
			masks = append(masks, f)
		}
	}
	return masks, nulls
}

// LookupKeyEntry will look up a key entry in the repository.  If the key entry is not
// found, it will return nil, nil.
func (r *Repository) LookupKeyEntry(ctx context.Context, withKeyId string, opt ...Option) (*KeyEntry, error) {
	if withKeyId == "" {
		return nil, fmt.Errorf("lookup kms key entry: missing key id %w", db.ErrNilParameter)
	}

	k := allocKeyEntry()
	if err := r.reader.LookupWhere(ctx, &k, "key_id = ?", withKeyId); err != nil {
		return nil, fmt.Errorf("lookup kms key entry: failed %w for %s", err, withKeyId)
	}
	return &k, nil
}

// DeleteKeyEntry will delete a key entry from the repository
func (r *Repository) DeleteKeyEntry(ctx context.Context, withKeyId string, opt ...Option) (int, error) {
	if withKeyId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete kms key entry: missing key id %w", db.ErrNilParameter)
	}
	k := allocKeyEntry()
	k.KeyId = withKeyId
	rowsDeleted, err := r.writer.Delete(ctx, &k)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete kms key entry: failed %w for %s", err, withKeyId)
	}
	return rowsDeleted, nil
}
