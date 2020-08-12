package kms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// Repository is the iam database repository
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new kms Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper, opt ...Option) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if wrapper == nil {
		return nil, errors.New("error creating db repository with nil wrapper")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		wrapper:      wrapper,
		defaultLimit: opts.withLimit,
	}, nil
}

// CreateExternalConfig inserts into the repository and returns the new external
// config with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateExternalConfig(ctx context.Context, conf *ExternalConfig, opt ...Option) (*ExternalConfig, error) {
	if conf == nil {
		return nil, fmt.Errorf("create external config: missing conf %w", db.ErrNilParameter)
	}
	if conf.ExternalConfig == nil {
		return nil, fmt.Errorf("create external config: missing conf store %w", db.ErrNilParameter)
	}
	if conf.PrivateId != "" {
		return nil, fmt.Errorf("create external config: private id not empty: %w", db.ErrInvalidParameter)
	}
	if conf.ScopeId == "" {
		return nil, fmt.Errorf("create external config: missing conf scope id: %w", db.ErrInvalidParameter)
	}
	if conf.Config == "" {
		return nil, fmt.Errorf("create external config: missing configuration: %w", db.ErrInvalidParameter)
	}
	id, err := newExternalConfigId()
	if err != nil {
		return nil, fmt.Errorf("create external config: %w", err)
	}
	c := conf.Clone().(*ExternalConfig)
	c.PrivateId = id
	if err := c.encrypt(ctx, r.wrapper); err != nil {
		return nil, fmt.Errorf("create external config: encrypt: %w", err)
	}

	var returnedConfig interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedConfig = c.Clone()
			if err := w.Create(ctx, returnedConfig, db.WithOplog(r.wrapper, c.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create external config: %w for %s", err, c.PrivateId)
	}
	return returnedConfig.(*ExternalConfig), err
}

// LookupExternalConfig will look up an external config in the repository.  If the config is not
// found, it will return nil, nil.
func (r *Repository) LookupExternalConfig(ctx context.Context, privateId string, opt ...Option) (*ExternalConfig, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup external config: missing private id %w", db.ErrNilParameter)
	}

	c := allocExternalConfig()
	c.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &c); err != nil {
		return nil, fmt.Errorf("lookup external config: failed %w for %s", err, privateId)
	}
	if err := c.decrypt(ctx, r.wrapper); err != nil {
		return nil, fmt.Errorf("lookup external config: encrypt: %w", err)
	}
	return &c, nil
}

// DeleteExternalConfig deletes the external config for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteExternalConfig(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete external config: missing private id: %w", db.ErrInvalidParameter)
	}
	c := allocExternalConfig()
	c.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &c); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete external config: failed %w for %s", err, privateId)
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			metadata := c.oplog(oplog.OpType_OP_TYPE_DELETE)
			dc := c.Clone()
			rowsDeleted, err = w.Delete(ctx, dc, db.WithOplog(r.wrapper, metadata))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete external config: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// UpdateExternalConfig will update an external config in the repository and
// return the written config. fieldMaskPaths provides field_mask.proto paths for
// fields that should be updated.  Fields will be set to NULL if the field is a
// zero value and included in fieldMask.  Config is the only updatable field,
// If no updatable fields are included in the fieldMaskPaths, then an error is
// returned.
func (r *Repository) UpdateExternalConfig(ctx context.Context, conf *ExternalConfig, version uint32, fieldMaskPaths []string, opt ...Option) (*ExternalConfig, int, error) {
	if conf == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update external config: missing conf %w", db.ErrNilParameter)
	}
	if conf.PrivateId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update external config: missing conf private id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("config", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update external config: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"config": conf.Config,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update external config: %w", db.ErrEmptyFieldMask)
	}

	var rowsUpdated int
	var returnedCfg interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			metadata := conf.oplog(oplog.OpType_OP_TYPE_UPDATE)
			returnedCfg = conf.Clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				returnedCfg,
				dbMask,
				nullFields,
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
		return nil, db.NoRowsAffected, fmt.Errorf("update external config: %w for %s", err, conf.PrivateId)
	}

	return returnedCfg.(*ExternalConfig), rowsUpdated, err
}
