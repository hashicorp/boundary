package servers

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/store"
)

const (
	// DefaultLiveness is the setting that controls the server "liveness" time,
	// or the maximum allowable time that a worker can't send a status update to
	// the controller for. After this, the server is considered dead, and it will
	// be taken out of the rotation for allowable workers for connections, and
	// connections will possibly start to be terminated and marked as closed
	// depending on the grace period setting (see
	// base.Server.StatusGracePeriodDuration). This value serves as the default
	// and minimum allowable setting for the grace period.
	DefaultLiveness = 15 * time.Second
)

type ServerType string

const (
	ServerTypeController ServerType = "controller"
	ServerTypeWorker     ServerType = "worker"
)

func (s ServerType) String() string {
	return string(s)
}

// Repository is the servers database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepository creates a new servers Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms) (*Repository, error) {
	const op = "servers.NewRepository"
	if r == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil kms")
	}
	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}

// ListWorkers is a passthrough to listWorkersWithReader that uses the repo's normal reader.
func (r *Repository) ListWorkers(ctx context.Context, opt ...Option) ([]*store.Worker, error) {
	return r.listWorkersWithReader(ctx, r.reader, opt...)
}

// listWorkersWithReader will return a listing of resources and honor the WithLimit option or the repo
// defaultLimit. It accepts a reader, allowing it to be used within a transaction or without.
func (r *Repository) listWorkersWithReader(ctx context.Context, reader db.Reader, opt ...Option) ([]*store.Worker, error) {
	opts := getOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = DefaultLiveness
	}

	var where string
	if liveness > 0 {
		where = fmt.Sprintf("update_time > now() - interval '%d seconds'", uint32(liveness.Seconds()))
	}

	var workers []*store.Worker
	if err := reader.SearchWhere(
		ctx,
		&workers,
		where,
		[]interface{}{},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, "workers.listWorkersWithReader")
	}

	return workers, nil
}

func (r *Repository) ListControllers(ctx context.Context, opt ...Option) ([]*store.Controller, error) {
	return r.listControllersWithReader(ctx, r.reader, opt...)
}

// listControllersWithReader will return a listing of resources and honor the
// WithLimit option or the repo defaultLimit. It accepts a reader, allowing it
// to be used within a transaction or without.
func (r *Repository) listControllersWithReader(ctx context.Context, reader db.Reader, opt ...Option) ([]*store.Controller, error) {
	opts := getOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = DefaultLiveness
	}

	var where string
	if liveness > 0 {
		where = fmt.Sprintf("update_time > now() - interval '%d seconds'", uint32(liveness.Seconds()))
	}

	var controllers []*store.Controller
	if err := reader.SearchWhere(
		ctx,
		&controllers,
		where,
		[]interface{}{},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, "workers.listControllersWithReader")
	}

	return controllers, nil
}

// WorkerTag holds the information for the worker_tag table for Gorm.
type WorkerTag struct {
	WorkerId string
	Key      string
	Value    string
}

// ListTagsForWorkers pulls out tag tuples into WorkerTag structs for the given worker
func (r *Repository) ListTagsForWorkers(ctx context.Context, workerIds []string, opt ...Option) ([]*WorkerTag, error) {
	var workerTags []*WorkerTag
	if err := r.reader.SearchWhere(
		ctx,
		&workerTags,
		"worker_id in (?)",
		[]interface{}{workerIds},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, "servers.ListTagsForWorkers", errors.WithMsg(fmt.Sprintf("worker IDs %v", workerIds)))
	}
	return workerTags, nil
}

func (r *Repository) UpsertWorker(ctx context.Context, worker *store.Worker, opt ...Option) ([]*store.Controller, int, error) {
	const op = "servers.UpsertWorker"

	if worker == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "worker is nil")
	}

	opts := getOpts(opt...)

	var rowsUpdated int64
	var controllers []*store.Controller
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			onConflict := &db.OnConflict{
				Target: db.Columns{"private_id"},
				Action: append(db.SetColumns([]string{"description", "address"}), db.SetColumnValues(map[string]interface{}{"update_time": "now()"})...),
			}
			err = w.Create(ctx, worker, db.WithOnConflict(onConflict), db.WithReturnRowsAffected(&rowsUpdated))
			if err != nil {
				return errors.Wrap(ctx, err, op+":Upsert")
			}

			// Fetch current controllers to feed to the workers
			controllers, err = r.listControllersWithReader(ctx, read)
			if err != nil {
				return errors.Wrap(ctx, err, op+":ListController")
			}

			// If we've been told to update tags, we need to clean out old
			// ones and add new ones. Within the current transaction, simply
			// delete all tags for the given worker, then add the new ones
			// we've been sent.
			if opts.withUpdateTags {
				_, err = w.Delete(ctx, &WorkerTag{}, db.WithWhere(deleteTagsSql, worker.PrivateId))
				if err != nil {
					return errors.Wrap(ctx, err, op+":DeleteTags", errors.WithMsg(worker.PrivateId))
				}

				// If tags were cleared out entirely, then we'll have nothing
				// to do here, e.g., it will result in deletion of all tags.
				// Otherwise, go through and stage each tuple for insertion
				// below.
				if len(worker.Tags) > 0 {
					tags := make([]interface{}, 0, len(worker.Tags))
					for k, v := range worker.Tags {
						if v == nil {
							return errors.New(ctx, errors.InvalidParameter, op+":RangeTags", fmt.Sprintf("found nil tag value for worker %s and key %s", worker.PrivateId, k))
						}
						for _, val := range v.Values {
							tags = append(tags, WorkerTag{
								WorkerId: worker.PrivateId,
								Key:      k,
								Value:    val,
							})
						}
					}
					if err = w.CreateItems(ctx, tags); err != nil {
						return errors.Wrap(ctx, err, op+":CreateTags", errors.WithMsg(worker.PrivateId))
					}
				}
			}

			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, err
	}

	return controllers, int(rowsUpdated), nil
}

func (r *Repository) UpsertController(ctx context.Context, controller *store.Controller) (int, error) {
	const op = "servers.UpsertController"

	if controller == nil {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "controller is nil")
	}

	var rowsUpdated int64
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			onConflict := &db.OnConflict{
				Target: db.Columns{"private_id"},
				Action: append(db.SetColumns([]string{"description", "address"}), db.SetColumnValues(map[string]interface{}{"update_time": "now()"})...),
			}
			err = w.Create(ctx, controller, db.WithOnConflict(onConflict), db.WithReturnRowsAffected(&rowsUpdated))
			if err != nil {
				return errors.Wrap(ctx, err, op+":Upsert")
			}

			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, err
	}

	return int(rowsUpdated), nil
}

type Nonce struct {
	Nonce   string
	Purpose string
}

// TableName returns the table name.
func (n *Nonce) TableName() string {
	return "nonce"
}

const (
	NoncePurposeRecovery   = "recovery"
	NoncePurposeWorkerAuth = "worker-auth"
)

// AddNonce adds a nonce
func (r *Repository) AddNonce(ctx context.Context, nonce, purpose string, opt ...Option) error {
	const op = "servers.AddNonce"
	if nonce == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "empty nonce")
	}
	switch purpose {
	case NoncePurposeRecovery, NoncePurposeWorkerAuth:
	case "":
		return errors.New(ctx, errors.InvalidParameter, op, "empty nonce purpose")
	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown nonce purpose %q", purpose))
	}
	if err := r.writer.Create(ctx, &Nonce{
		Nonce:   nonce,
		Purpose: purpose,
	}); err != nil {
		return errors.Wrap(ctx, err, op+":Insertion")
	}
	return nil
}

// CleanupNonces removes nonces that no longer need to be stored
func (r *Repository) CleanupNonces(ctx context.Context, opt ...Option) (int, error) {
	// Use the largest validity period out of the various nonces we're looking at
	maxDuration := globals.RecoveryTokenValidityPeriod
	if globals.WorkerAuthNonceValidityPeriod > maxDuration {
		maxDuration = globals.WorkerAuthNonceValidityPeriod
	}
	// If something was inserted before 3x the actual validity period, clean it out
	endTime := time.Now().Add(-3 * maxDuration)

	rows, err := r.writer.Delete(ctx, &Nonce{}, db.WithWhere(deleteWhereCreateTimeSql, endTime))
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, "servers.CleanupNonces")
	}
	return rows, nil
}

// ListNonces lists nonces. Used only for tests at the moment.
func (r *Repository) ListNonces(ctx context.Context, purpose string, opt ...Option) ([]*Nonce, error) {
	var nonces []*Nonce
	if err := r.reader.SearchWhere(ctx, &nonces, "purpose = ?", []interface{}{purpose}, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, "servers.ListNonces")
	}
	return nonces, nil
}
