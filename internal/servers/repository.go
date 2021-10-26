package servers

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/resource"
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

// ListServers is a passthrough to listServersWithReader that uses the repo's
// normal reader.
func (r *Repository) ListServers(ctx context.Context, serverType ServerType, opt ...Option) ([]*Server, error) {
	return r.listServersWithReader(ctx, r.reader, serverType, opt...)
}

// listServersWithReader will return a listing of resources and honor the
// WithLimit option or the repo defaultLimit. It accepts a reader, allowing it
// to be used within a transaction or without.
func (r *Repository) listServersWithReader(ctx context.Context, reader db.Reader, serverType ServerType, opt ...Option) ([]*Server, error) {
	opts := getOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = DefaultLiveness
	}

	var where string
	if liveness > 0 {
		where = fmt.Sprintf("type = ? and update_time > now() - interval '%d seconds'", uint32(liveness.Seconds()))
	} else {
		where = "type = ?"
	}

	var servers []*Server
	if err := reader.SearchWhere(
		ctx,
		&servers,
		where,
		[]interface{}{serverType},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, "servers.listServersWithReader")
	}

	return servers, nil
}

// ServerTag holds the information for the server_tag table for Gorm.
type ServerTag struct {
	ServerId string
	Key      string
	Value    string
}

// TableName overrides the table name used by ServerTag to `server_tag`
func (ServerTag) TableName() string {
	return "server_tag"
}

// ListTagsForServers pulls out tag tuples into ServerTag structs for the
// given server ID values.
func (r *Repository) ListTagsForServers(ctx context.Context, serverIds []string, opt ...Option) ([]*ServerTag, error) {
	var serverTags []*ServerTag
	if err := r.reader.SearchWhere(
		ctx,
		&serverTags,
		"server_id in (?)",
		[]interface{}{serverIds},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, "servers.ListTagsForServers", errors.WithMsg(fmt.Sprintf("server IDs %v", serverIds)))
	}
	return serverTags, nil
}

// UpsertServer adds or updates a server in the DB
func (r *Repository) UpsertServer(ctx context.Context, server *Server, opt ...Option) ([]*Server, int, error) {
	const op = "servers.UpsertServer"

	if server == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "server is nil")
	}

	opts := getOpts(opt...)

	var rowsUpdated int64
	var controllers []*Server
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			onConflict := &db.OnConflict{
				Target: db.Constraint("server_pkey"),
				Action: append(db.SetColumns([]string{"type", "description", "address"}), db.SetColumnValues(map[string]interface{}{"update_time": "now()"})...),
			}
			err = w.Create(ctx, server, db.WithOnConflict(onConflict), db.WithReturnRowsAffected(&rowsUpdated))
			if err != nil {
				return errors.Wrap(ctx, err, op+":Upsert")
			}

			// If it's a worker, fetch the current controllers to feed to them
			if server.Type == resource.Worker.String() {
				// Fetch current controllers to feed to the workers
				controllers, err = r.listServersWithReader(ctx, read, ServerTypeController)
				if err != nil {
					return errors.Wrap(ctx, err, op+":ListServer")
				}
			}

			// If we've been told to update tags, we need to clean out old
			// ones and add new ones. Within the current transaction, simply
			// delete all tags for the given worker, then add the new ones
			// we've been sent.
			if opts.withUpdateTags {
				_, err = w.Delete(ctx, &ServerTag{}, db.WithWhere(deleteTagsSql, server.PrivateId))
				if err != nil {
					return errors.Wrap(ctx, err, op+":DeleteTags", errors.WithMsg(server.PrivateId))
				}

				// If tags were cleared out entirely, then we'll have nothing
				// to do here, e.g., it will result in deletion of all tags.
				// Otherwise, go through and stage each tuple for insertion
				// below.
				if len(server.Tags) > 0 {
					tags := make([]interface{}, 0, len(server.Tags))
					for k, v := range server.Tags {
						if v == nil {
							return errors.New(ctx, errors.InvalidParameter, op+":RangeTags", fmt.Sprintf("found nil tag value for worker %s and key %s", server.PrivateId, k))
						}
						for _, val := range v.Values {
							tags = append(tags, ServerTag{
								ServerId: server.PrivateId,
								Key:      k,
								Value:    val,
							})
						}
					}
					if err = w.CreateItems(ctx, tags); err != nil {
						return errors.Wrap(ctx, err, op+":CreateTags", errors.WithMsg(server.PrivateId))
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

type ServerNonce struct {
	Nonce   string
	Purpose string
}

// TableName returns the table name.
func (sn *ServerNonce) TableName() string {
	return "server_nonce"
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
	if err := r.writer.Create(ctx, &ServerNonce{
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

	rows, err := r.writer.Delete(ctx, &ServerNonce{}, db.WithWhere(deleteWhereCreateTimeSql, endTime))
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, "servers.CleanupNonces")
	}
	return rows, nil
}

// ListNonces lists nonces. Used only for tests at the moment.
func (r *Repository) ListNonces(ctx context.Context, purpose string, opt ...Option) ([]*ServerNonce, error) {
	var nonces []*ServerNonce
	if err := r.reader.SearchWhere(ctx, &nonces, "purpose = ?", []interface{}{purpose}, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, "servers.ListNonces")
	}
	return nonces, nil
}
