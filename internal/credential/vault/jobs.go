package vault

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
	ua "go.uber.org/atomic"
)

const (
	tokenRenewalJobName      = "vault_token_renewal"
	credentialRenewalJobName = "vault_credential_renewal"

	defaultNextRunIn = 5 * time.Minute
	renewalWindow    = 10 * time.Minute
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

// NewTokenRenewalJob creates a new in TokenRenewalJob.
//
// WithLimit is the only supported option.
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
// of tokens that are set to be renewed. Completed is the number of tokens already renewed.
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
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, op)
	}

	var ps []*privateStore
	// Fetch all tokens that will reach their renewal point within the renewalWindow.
	// This is done to avoid constantly scheduling the token renewal job when there are multiple tokens
	// set to renew in sequence.
	err := r.reader.SearchWhere(ctx, &ps, `token_renewal_time < wt_add_seconds_to_now(?)`, []interface{}{renewalWindow.Seconds()}, db.WithLimit(r.limit))
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

	next, err := nextRenewal(r)
	if err != nil {
		return defaultNextRunIn, errors.Wrap(err, op)
	}
	return next, nil
}

func nextRenewal(j scheduler.Job) (time.Duration, error) {
	const op = "vault.nextRenewal"

	var query string
	var r db.Reader
	switch job := j.(type) {
	case *TokenRenewalJob:
		query = tokenRenewalNextRunInQuery
		r = job.reader
	case *CredentialRenewalJob:
		query = credentialRenewalNextRunInQuery
		r = job.reader
	default:
		return 0, errors.New(errors.Unknown, op, "unknown job")
	}

	rows, err := r.Query(context.Background(), query, nil)
	if err != nil {
		return 0, errors.Wrap(err, op)
	}
	defer rows.Close()

	for rows.Next() {
		type NextRenewal struct {
			RenewalIn time.Duration
		}
		var n NextRenewal
		err = r.ScanRows(rows, &n)
		if err != nil {
			return 0, errors.Wrap(err, op)
		}
		if n.RenewalIn < 0 {
			// If we are past the next renewal time, return 0 to schedule immediately
			return 0, nil
		}
		return n.RenewalIn * time.Second, nil
	}

	return defaultNextRunIn, nil
}

// Name is the unique name of the job.
func (r *TokenRenewalJob) Name() string {
	return tokenRenewalJobName
}

// Description is the human readable description of the job.
func (r *TokenRenewalJob) Description() string {
	return "Periodically renews Vault credential store tokens that are in a maintaining or current state."
}

type renewableCredential struct {
	*Credential
	Library     *privateLibrary `gorm:"embedded"`
	RenewalTime *timestamp.Timestamp
}

// TableName returns the table name for gorm.
func (c *renewableCredential) TableName() string {
	return "credential_renewable_vault_credential"
}

// CredentialRenewalJob is the recurring job that renews Vault credentials issued to a session.
// The CredentialRenewalJob is not thread safe, an attempt to Run the job concurrently will result
// in an JobAlreadyRunning error.
type CredentialRenewalJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	logger hclog.Logger
	limit  int

	running      ua.Bool
	numCreds     int
	numProcessed int
}

// NewCredentialRenewalJob creates a new in CredentialRenewalJob.
//
// WithLimit is the only supported option.
func NewCredentialRenewalJob(r db.Reader, w db.Writer, kms *kms.Kms, logger hclog.Logger, opt ...Option) (*CredentialRenewalJob, error) {
	const op = "vault.NewCredentialRenewalJob"
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
	return &CredentialRenewalJob{
		reader: r,
		writer: w,
		kms:    kms,
		logger: logger,
		limit:  opts.withLimit,
	}, nil
}

// Status returns the current status of the credential renewal job.  Total is the total number
// of credentials that are set to be renewed.  Completed is the number of credential already renewed.
func (r *CredentialRenewalJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.numProcessed,
		Total:     r.numCreds,
	}
}

// Run queries the vault credential repo for credentials that need to be renewed, it then creates
// a vault client and renews each credential.  Can not be run in parallel, if Run is invoked while
// already running an error with code JobAlreadyRunning will be returned.
func (r *CredentialRenewalJob) Run(ctx context.Context) error {
	const op = "vault.(CredentialRenewalJob).Run"

	if !r.running.CAS(r.running.Load(), true) {
		return errors.New(errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, op)
	}

	var creds []*renewableCredential
	// Fetch all credentials that will reach their renewal point within the renewalWindow.
	// This is done to avoid constantly scheduling the credential renewal job when there are
	// multiple credentials set to renew in sequence.
	err := r.reader.SearchWhere(ctx, &creds, `renewal_time < wt_add_seconds_to_now(?)`, []interface{}{renewalWindow.Seconds()}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(err, op)
	}

	// Set numProcessed and numTokens for status report
	r.numProcessed, r.numCreds = 0, len(creds)

	for _, c := range creds {
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(err, op)
		}

		if err := r.renewCred(ctx, c); err != nil {
			r.logger.Error("error renewing credential", "credential id", c.PublicId, "error", err)
		}

		r.numProcessed++
	}

	return nil
}

func (r *CredentialRenewalJob) renewCred(ctx context.Context, c *renewableCredential) error {
	const op = "vault.(TokenRenewalJob).renewToken"

	databaseWrapper, err := r.kms.GetWrapper(ctx, c.Library.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	if err = c.Library.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(err, op)
	}

	vc, err := c.Library.client()
	if err != nil {
		return errors.Wrap(err, op)
	}

	// Subtract last renewal time from previous expiration time to get lease duration
	leaseDuration := c.ExpirationTime.AsTime().Sub(c.LastRenewalTime.AsTime())
	renewedCred, err := vc.renewLease(c.ExternalId, leaseDuration)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to renew vault token"))
	}

	cred := c.Credential.clone()
	cred.expiration = time.Duration(renewedCred.LeaseDuration) * time.Second
	query, values := cred.updateExpirationQuery()
	numRows, err := r.writer.Exec(ctx, query, values)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if numRows != 1 {
		return errors.New(errors.Unknown, op, "credential renewed but failed to update repo")
	}

	return nil
}

// NextRunIn queries the vault credential repo to determine when the next credential renewal job should run.
func (r *CredentialRenewalJob) NextRunIn() (time.Duration, error) {
	const op = "vault.(CredentialRenewalJob).NextRunIn"

	next, err := nextRenewal(r)
	if err != nil {
		return defaultNextRunIn, errors.Wrap(err, op)
	}
	return next, nil
}

// Name is the unique name of the job.
func (r *CredentialRenewalJob) Name() string {
	return credentialRenewalJobName
}

// Description is the human readable description of the job.
func (r *CredentialRenewalJob) Description() string {
	return "Periodically renews Vault credentials that are still attached to a non-terminated session."
}
