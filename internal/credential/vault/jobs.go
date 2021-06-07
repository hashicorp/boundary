package vault

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
	ua "go.uber.org/atomic"
)

const (
	tokenRenewalJobName = "vault_token_renewal"

	defaultTokenRenewalInterval = 5 * time.Minute
	tokenRenewalWindow          = 10 * time.Minute
)

// TokenRenewalJob is the recurring job that renews credential store Vault tokens that
// are in the `current` and `maintaining` state.  The TokenRenewalJob is not thread safe,
// an attempt to Run the job concurrently will result in an JobAlreadyRunning error.
type TokenRenewalJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	logger hclog.Logger
	limit  int

	running      ua.Bool
	numTokens    int
	numProcessed int
}

// NewTokenRenewalJob creates a new in TokenRenewalJob
func NewTokenRenewalJob(r db.Reader, w db.Writer, kms *kms.Kms, logger hclog.Logger, opt ...Option) (*TokenRenewalJob, error) {
	const op = "vault.NewTokenRenewalJob"
	switch {
	case r == nil:
		return nil, errors.New(errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(errors.InvalidParameter, op, "missing kms")
	case logger == nil:
		return nil, errors.New(errors.InvalidParameter, op, "missing logger")
	}

	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &TokenRenewalJob{
		reader: r,
		writer: w,
		kms:    kms,
		logger: logger,
		limit:  opts.withLimit,
	}, nil
}

// Status returns the current status of the token renewal job.  Total is the total number
// of tokens that are set to be returned and completed is the number of tokens already renewed.
func (r *TokenRenewalJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.numProcessed,
		Total:     r.numTokens,
	}
}

// Run queries the vault credential repo for tokens that need to be renewed, it then creates
// a vault client and renews each token.  Can not be run in parallel, if Run is invoked while
// already running an error with code JobAlreadyRunning will be returned.
func (r *TokenRenewalJob) Run(ctx context.Context) error {
	const op = "vault.(TokenRenewalJob).Run"

	if !r.running.CAS(r.running.Load(), true) {
		return errors.New(errors.JobAlreadyRunning, op, "job already running")
	}

	// Clear running flag
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, op)
	}

	var ps []*privateStore
	// Fetch all tokens that will reach their renewal point within the tokenRenewalWindow.
	// This is done to avoid constantly scheduling the token renewal job when there are multiple tokens
	// set to renew in sequence.
	err := r.reader.SearchWhere(ctx, &ps, `token_renewal_time < wt_add_seconds_to_now(?)`, []interface{}{tokenRenewalWindow.Seconds()}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(err, op)
	}

	// Set numProcessed and numTokens for status report
	r.numProcessed, r.numTokens = 0, len(ps)

	for _, s := range ps {
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(err, op)
		}

		if err := r.renewToken(ctx, s); err != nil {
			r.logger.Error("error renewing token", "credential store id", s.StoreId, "token status", s.TokenStatus, "error", err)
		}

		r.numProcessed++
	}

	return nil
}

func (r *TokenRenewalJob) renewToken(ctx context.Context, s *privateStore) error {
	const op = "vault.(TokenRenewalJob).renewToken"
	databaseWrapper, err := r.kms.GetWrapper(ctx, s.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	if err = s.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(err, op)
	}

	token := s.token()
	if token == nil {
		// Store has no token to renew
		return nil
	}

	vc, err := s.client()
	if err != nil {
		return errors.Wrap(err, op)
	}

	var respErr *vault.ResponseError
	renewedToken, err := vc.renewToken()
	if ok := errors.As(err, &respErr); ok && respErr.StatusCode == http.StatusForbidden {
		// Vault returned a 403 when attempting a renew self, the token is either expired
		// or malformed.  Set status to "expired" so credentials created with token can be
		// cleaned up.

		query, values := token.updateStatusQuery(ExpiredToken)
		numRows, err := r.writer.Exec(ctx, query, values)
		if err != nil {
			return errors.Wrap(err, op)
		}
		if numRows != 1 {
			return errors.New(errors.Unknown, op, "token expired but failed to update repo")
		}
		if s.TokenStatus == string(CurrentToken) {
			r.logger.Info("Vault credential store current token has expired", "credential store id", s.StoreId)
		}

		return nil
	}
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to renew vault token"))
	}

	tokenExpires, err := renewedToken.TokenTTL()
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get vault token expiration"))
	}

	token.expiration = tokenExpires
	query, values := token.updateExpirationQuery()
	numRows, err := r.writer.Exec(ctx, query, values)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if numRows != 1 {
		return errors.New(errors.Unknown, op, "token renewed but failed to update repo")
	}

	return nil
}

// NextRunIn queries the vault credential repo to determine when the next token renewal job should run.
func (r *TokenRenewalJob) NextRunIn() (time.Duration, error) {
	const op = "vault.(TokenRenewalJob).NextRunIn"

	rows, err := r.reader.Query(context.Background(), tokenRenewalNextRunInQuery, nil)
	if err != nil {
		return defaultTokenRenewalInterval, errors.Wrap(err, op)
	}
	defer rows.Close()

	for rows.Next() {
		type NextRenewal struct {
			RenewalIn time.Duration
		}
		var n NextRenewal
		err = r.reader.ScanRows(rows, &n)
		if err != nil {
			return defaultTokenRenewalInterval, errors.Wrap(err, op)
		}
		if n.RenewalIn < 0 {
			// If we are past the next renewal time, return 0 to schedule immediately
			return 0, nil
		}
		return n.RenewalIn * time.Second, nil
	}

	return defaultTokenRenewalInterval, nil
}

// Name is the unique name of the job.
func (r *TokenRenewalJob) Name() string {
	return tokenRenewalJobName
}

// Description is the human readable description of the job.
func (r *TokenRenewalJob) Description() string {
	return "Periodically renews Vault credential store tokens that are in a maintaining or current state."
}
