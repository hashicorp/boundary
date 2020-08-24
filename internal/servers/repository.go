package servers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/resource"
)

const (
	defaultLiveness = 15 * time.Second
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
	if r == nil {
		return nil, errors.New("error creating server repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating server repository with nil writer")
	}
	if kms == nil {
		return nil, errors.New("error creating server repository with nil kms")
	}
	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) ListServers(ctx context.Context, serverType ServerType, opt ...Option) ([]*Server, error) {
	opts := getOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = defaultLiveness
	}
	updateTime := time.Now().Add(-1 * liveness)
	q := `
	select * from servers
	where
		type = $1
		and
		update_time > $2;`
	underlying, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("error fetching underlying DB for server list operation: %w", err)
	}
	rows, err := underlying.QueryContext(ctx, q,
		serverType.String(),
		updateTime.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("error performing server list: %w", err)
	}
	results := make([]*Server, 0, 3)
	var scanErr error
	for rows.Next() {
		server := &Server{
			CreateTime: new(timestamp.Timestamp),
			UpdateTime: new(timestamp.Timestamp),
		}
		if err := rows.Scan(
			&server.PrivateId,
			&server.Type,
			&server.Name,
			&server.Description,
			&server.Address,
			server.CreateTime,
			server.UpdateTime,
		); err != nil {
			scanErr = fmt.Errorf("error scanning server row: %w", err)
			break
		}
		results = append(results, server)
	}
	if scanErr != nil {
		return nil, scanErr
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error performing scan over server rows: %w", err)
	}
	return results, nil
}

// UpsertServer adds or updates a server in the DB
func (r *Repository) UpsertServer(ctx context.Context, server *Server, opt ...Option) ([]*Server, int, error) {
	if server == nil {
		return nil, db.NoRowsAffected, errors.New("cannot update server that is nil")
	}
	// Ensure, for now at least, the private ID is always equivalent to the name
	server.PrivateId = server.Name
	// Build query
	q := `
	insert into servers
		(private_id, type, name, description, address, update_time)
	values
		($1, $2, $3, $4, $5, $6)
	on conflict on constraint servers_pkey
	do update set
		name = $3,
		description = $4,
		address = $5,
		update_time = $6;
	`
	underlying, err := r.writer.DB()
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("error fetching underlying DB for upsert operation: %w", err)
	}
	result, err := underlying.ExecContext(ctx, q,
		server.PrivateId,
		server.Type,
		server.Name,
		server.Description,
		server.Address,
		time.Now().Format(time.RFC3339))
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("error performing status upsert: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("unable to fetch number of rows affected from query: %w", err)
	}
	// If updating a controller, done
	if server.Type == resource.Controller.String() {
		return nil, int(rowsAffected), nil
	}
	// Fetch current controllers to feed to the workers
	controllers, err := r.ListServers(ctx, ServerTypeController)
	return controllers, len(controllers), err
}

type RecoveryNonce struct {
	Nonce string
}

// AddRecoveryNonce adds a nonce
func (r *Repository) AddRecoveryNonce(ctx context.Context, nonce string, opt ...Option) error {
	if nonce == "" {
		return errors.New("empty nonce provided")
	}
	rn := &RecoveryNonce{Nonce: nonce}
	if err := r.writer.Create(ctx, rn); err != nil {
		return fmt.Errorf("error performing nonce insertion: %w", err)
	}
	return nil
}

// CleanupNonces removes nonces that no longer need to be stored
func (r *Repository) CleanupNonces(ctx context.Context, opt ...Option) (int, error) {
	// If something was inserted before 3x the actual validity period, clean it out
	endTime := time.Now().Add(-3 * globals.RecoveryTokenValidityPeriod)

	rows, err := r.writer.Delete(ctx, &RecoveryNonce{}, db.WithWhere(deleteWhereSql, endTime))
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("error performing nonce cleanup: %w", err)
	}
	return rows, nil
}

// ListNonces lists nonces. Used only for tests at the moment.
func (r *Repository) ListNonces(ctx context.Context, opt ...Option) ([]*RecoveryNonce, error) {
	var nonces []*RecoveryNonce
	if err := r.reader.SearchWhere(ctx, &nonces, "", nil, db.WithLimit(-1)); err != nil {
		return nil, fmt.Errorf("error listing nonces: %w", err)
	}
	return nonces, nil
}
