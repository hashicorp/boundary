// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	vault "github.com/hashicorp/vault/api"
	ua "go.uber.org/atomic"
)

const (
	tokenRenewalJobName           = "vault_token_renewal"
	tokenRevocationJobName        = "vault_token_revocation"
	credentialRenewalJobName      = "vault_credential_renewal"
	credentialRevocationJobName   = "vault_credential_revocation"
	credentialStoreCleanupJobName = "vault_credential_store_cleanup"
	credentialCleanupJobName      = "vault_credential_cleanup"

	defaultNextRunIn = 5 * time.Minute
	renewalWindow    = 10 * time.Minute
)

func RegisterJobs(ctx context.Context, scheduler *scheduler.Scheduler, r db.Reader, w db.Writer, kms *kms.Kms) error {
	const op = "vault.RegisterJobs"
	tokenRenewal, err := newTokenRenewalJob(ctx, r, w, kms)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, tokenRenewal); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("token renewal job"))
	}
	tokenRevoke, err := newTokenRevocationJob(ctx, r, w, kms)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, tokenRevoke); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("token revocation job"))
	}
	credRenewal, err := newCredentialRenewalJob(ctx, r, w, kms)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, credRenewal); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("credential renewal job"))
	}
	credRevoke, err := newCredentialRevocationJob(ctx, r, w, kms)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, credRevoke); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("credential revocation job"))
	}
	credStoreCleanup, err := newCredentialStoreCleanupJob(ctx, r, w, kms)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, credStoreCleanup); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("credential store cleanup job"))
	}
	credCleanup, err := newCredentialCleanupJob(ctx, w)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, credCleanup); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("credential cleanup job"))
	}
	return nil
}

// TokenRenewalJob is the recurring job that renews credential store Vault tokens that
// are in the `current` and `maintaining` state.  The TokenRenewalJob is not thread safe,
// an attempt to Run the job concurrently will result in an JobAlreadyRunning error.
type TokenRenewalJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	limit  int

	running      ua.Bool
	numTokens    int
	numProcessed int
}

// newTokenRenewalJob creates a new in-memory TokenRenewalJob.
//
// WithLimit is the only supported option.
func newTokenRenewalJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*TokenRenewalJob, error) {
	const op = "vault.newTokenRenewalJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
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
func (r *TokenRenewalJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "vault.(TokenRenewalJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var ps []*renewRevokeStore
	// Fetch all tokens that will reach their renewal point within the renewalWindow.
	// This is done to avoid constantly scheduling the token renewal job when there are multiple tokens
	// set to renew in sequence.
	err := r.reader.SearchWhere(ctx, &ps, `token_renewal_time < wt_add_seconds_to_now(?)`, []any{renewalWindow.Seconds()}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numTokens for status report
	r.numProcessed, r.numTokens = 0, len(ps)

	for _, as := range ps {
		s := as.Store
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := r.renewToken(ctx, s); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error renewing token", "credential store id", s.PublicId, "token status", s.TokenStatus))
		}
		r.numProcessed++
	}

	return nil
}

func isForbiddenError(err error) bool {
	var respErr *vault.ResponseError
	ok := errors.As(err, &respErr)
	return ok && respErr.StatusCode == http.StatusForbidden
}

func (r *TokenRenewalJob) renewToken(ctx context.Context, s *clientStore) error {
	const op = "vault.(TokenRenewalJob).renewToken"
	databaseWrapper, err := r.kms.GetWrapper(ctx, s.ProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err = s.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	token := s.token()
	if token == nil {
		// Store has no token to renew
		return nil
	}

	vc, err := s.client(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	renewedToken, err := vc.renewToken(ctx)
	if err != nil {
		// Vault returned a 403 when attempting a renew self, the token is either expired
		// or malformed.  Set status to "expired" so credentials created with token can be
		// cleaned up.
		// Also, check if the token has already expired based on time to avoid attempting
		// to renew the expired token against an Vault server that may no longer exist.
		if isForbiddenError(err) || time.Now().After(token.ExpirationTime.AsTime()) {
			query, values := token.updateStatusQuery(ExpiredToken)
			numRows, err := r.writer.Exec(ctx, query, values)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if numRows != 1 {
				return errors.New(ctx, errors.Unknown, op, "token expired but failed to update repo")
			}
			if s.TokenStatus == string(CurrentToken) {
				event.WriteSysEvent(ctx, op, "Vault credential store current token has expired", "credential store id", s.PublicId)
			}

			// Set credentials associated with this token to expired as Vault will already cascade delete them
			_, err = r.writer.Exec(ctx, updateCredentialStatusByTokenQuery, []any{ExpiredCredential, token.TokenHmac})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error updating credentials to revoked after revoking token"))
			}
			// exit early as we mark the token as expired
			return nil
		}
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to renew vault token"))
	}

	tokenExpires, err := renewedToken.TokenTTL()
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get vault token expiration"))
	}

	token.expiration = tokenExpires
	query, values := token.updateExpirationQuery()
	numRows, err := r.writer.Exec(ctx, query, values)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if numRows != 1 {
		return errors.New(ctx, errors.Unknown, op, "token renewed but failed to update repo")
	}

	return nil
}

// NextRunIn queries the vault credential repo to determine when the next token renewal job should run.
func (r *TokenRenewalJob) NextRunIn(ctx context.Context) (time.Duration, error) {
	const op = "vault.(TokenRenewalJob).NextRunIn"
	next, err := nextRenewal(ctx, r)
	if err != nil {
		return defaultNextRunIn, errors.Wrap(ctx, err, op)
	}

	return next, nil
}

func nextRenewal(ctx context.Context, j scheduler.Job) (time.Duration, error) {
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
		return 0, errors.New(ctx, errors.Unknown, op, "unknown job")
	}

	rows, err := r.Query(context.Background(), query, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	if rows.Next() {
		type NextRenewal struct {
			RenewalIn time.Duration
		}
		var n NextRenewal
		err = r.ScanRows(ctx, rows, &n)
		if err != nil {
			return 0, errors.Wrap(ctx, err, op)
		}
		if n.RenewalIn < 0 {
			// If we are past the next renewal time, return 0 to schedule immediately
			return 0, nil
		}
		return n.RenewalIn * time.Second, nil
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op)
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

// TokenRevocationJob is the recurring job that revokes credential store Vault tokens that
// are in the `maintaining` state and have no credentials being used by an active or pending session.
// The TokenRevocationJob is not thread safe, an attempt to Run the job concurrently will result in
// an JobAlreadyRunning error.
type TokenRevocationJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	limit  int

	running      ua.Bool
	numTokens    int
	numProcessed int
}

// newTokenRevocationJob creates a new in-memory TokenRevocationJob.
//
// WithLimit is the only supported option.
func newTokenRevocationJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*TokenRevocationJob, error) {
	const op = "vault.newTokenRevocationJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &TokenRevocationJob{
		reader: r,
		writer: w,
		kms:    kms,
		limit:  opts.withLimit,
	}, nil
}

// Status returns the current status of the token revocation job.  Total is the total number
// of tokens that are set to be revoked. Completed is the number of tokens already revoked.
func (r *TokenRevocationJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.numProcessed,
		Total:     r.numTokens,
	}
}

// Run queries the vault credential repo for tokens that need to be revoked, it then creates
// a vault client and revokes each token.  Can not be run in parallel, if Run is invoked while
// already running an error with code JobAlreadyRunning will be returned.
func (r *TokenRevocationJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "vault.(TokenRevocationJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Fetch all tokens in the revoke state as well as all tokens in the maintaining state
	// that have no credentials in an active state.
	where := `
token_status = 'revoke'
or
(token_status = 'maintaining'
  and token_hmac not in (
    select token_hmac from credential_vault_credential 
     where status = 'active'
))
`

	var ps []*renewRevokeStore
	err := r.reader.SearchWhere(ctx, &ps, where, nil, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numTokens for s report
	r.numProcessed, r.numTokens = 0, len(ps)
	for _, as := range ps {
		s := as.Store
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := r.revokeToken(ctx, s); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error revoking token", "credential store id", s.PublicId))
		}
		r.numProcessed++
	}

	return nil
}

func (r *TokenRevocationJob) revokeToken(ctx context.Context, s *clientStore) error {
	const op = "vault.(TokenRevocationJob).revokeToken"
	databaseWrapper, err := r.kms.GetWrapper(ctx, s.ProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err = s.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	token := s.token()
	if token == nil {
		// Store has no token to revoke
		return nil
	}

	vc, err := s.client(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var respErr *vault.ResponseError
	err = vc.revokeToken(ctx)
	if ok := errors.As(err, &respErr); ok && respErr.StatusCode == http.StatusForbidden {
		// Vault returned a 403 when attempting a revoke self, the token is already expired.
		// Clobber error and set status to "revoked" below.
		err = nil
	}
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to revoke vault token"))
	}

	query, values := token.updateStatusQuery(RevokedToken)
	numRows, err := r.writer.Exec(ctx, query, values)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if numRows != 1 {
		return errors.New(ctx, errors.Unknown, op, "token revoked but failed to update repo")
	}

	// Set credentials associated with this token to revoked as Vault will already cascade revoke them
	_, err = r.writer.Exec(ctx, updateCredentialStatusByTokenQuery, []any{RevokedCredential, token.TokenHmac})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error updating credentials to revoked after revoking token"))
	}

	return nil
}

// NextRunIn determines when the next token revocation job should run.
func (r *TokenRevocationJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return defaultNextRunIn, nil
}

// Name is the unique name of the job.
func (r *TokenRevocationJob) Name() string {
	return tokenRevocationJobName
}

// Description is the human readable description of the job.
func (r *TokenRevocationJob) Description() string {
	return "Periodically revokes Vault credential store tokens that are in a maintaining state and have no active credentials associated."
}

// CredentialRenewalJob is the recurring job that renews Vault credentials issued to a session.
// The CredentialRenewalJob is not thread safe, an attempt to Run the job concurrently will result
// in an JobAlreadyRunning error.
type CredentialRenewalJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	limit  int

	running      ua.Bool
	numCreds     int
	numProcessed int
}

// newCredentialRenewalJob creates a new in-memory CredentialRenewalJob.
//
// WithLimit is the only supported option.
func newCredentialRenewalJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*CredentialRenewalJob, error) {
	const op = "vault.newCredentialRenewalJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
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
func (r *CredentialRenewalJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "vault.(CredentialRenewalJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var creds []*privateCredential
	// Fetch all active credentials that will reach their renewal point within the renewalWindow.
	// This is done to avoid constantly scheduling the credential renewal job when there are
	// multiple credentials set to renew in sequence.
	err := r.reader.SearchWhere(ctx, &creds, `renewal_time < wt_add_seconds_to_now(?) and status = ?`, []any{renewalWindow.Seconds(), ActiveCredential}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numTokens for status report
	r.numProcessed, r.numCreds = 0, len(creds)
	for _, c := range creds {
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		if c.SessionCorrelationId != "" {
			ctx, err = event.NewCorrelationIdContext(ctx, c.SessionCorrelationId)
			if err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error generating correlation context", "credential id", c.PublicId, "session id", c.SessionId))
				continue
			}
		}

		if err := r.renewCred(ctx, c); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error renewing credential", "credential id", c.PublicId))
		}

		r.numProcessed++
	}

	return nil
}

func (r *CredentialRenewalJob) renewCred(ctx context.Context, c *privateCredential) error {
	const op = "vault.(CredentialRenewalJob).renewCred"
	databaseWrapper, err := r.kms.GetWrapper(ctx, c.ProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err = c.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	vc, err := c.client(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	cred := c.toCredential()

	var respErr *vault.ResponseError
	// Subtract last renewal time from previous expiration time to get lease duration
	leaseDuration := c.ExpirationTime.AsTime().Sub(c.LastRenewalTime.AsTime())
	renewedCred, err := vc.renewLease(ctx, c.ExternalId, leaseDuration)
	if ok := errors.As(err, &respErr); ok && respErr.StatusCode == http.StatusBadRequest {
		// Vault returned a 400 when attempting a renew lease, the lease is either expired
		// or the leaseId is malformed.  Set status to "expired".
		query, values := cred.updateStatusQuery(ExpiredCredential)
		numRows, err := r.writer.Exec(ctx, query, values)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if numRows != 1 {
			return errors.New(ctx, errors.Unknown, op, "credential expired but failed to update repo")
		}
		return nil
	}
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to renew credential"))
	}
	if renewedCred == nil {
		return errors.New(ctx, errors.Unknown, op, "vault returned empty credential")
	}

	cred.expiration = time.Duration(renewedCred.LeaseDuration) * time.Second
	query, values := cred.updateExpirationQuery()
	numRows, err := r.writer.Exec(ctx, query, values)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if numRows != 1 {
		return errors.New(ctx, errors.Unknown, op, "credential renewed but failed to update repo")
	}

	return nil
}

// NextRunIn queries the vault credential repo to determine when the next credential renewal job should run.
func (r *CredentialRenewalJob) NextRunIn(ctx context.Context) (time.Duration, error) {
	const op = "vault.(CredentialRenewalJob).NextRunIn"
	next, err := nextRenewal(ctx, r)
	if err != nil {
		return defaultNextRunIn, errors.Wrap(ctx, err, op)
	}

	return next, nil
}

// Name is the unique name of the job.
func (r *CredentialRenewalJob) Name() string {
	return credentialRenewalJobName
}

// Description is the human readable description of the job.
func (r *CredentialRenewalJob) Description() string {
	return "Periodically renews Vault credentials that are attached to an active/pending session (in the active state)."
}

// CredentialRevocationJob is the recurring job that revokes Vault credentials that are no
// longer being used by an active or pending session.
// The CredentialRevocationJob is not thread safe, an attempt to Run the job concurrently
// will result in an JobAlreadyRunning error.
type CredentialRevocationJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	limit  int

	running      ua.Bool
	numCreds     int
	numProcessed int
}

// newCredentialRevocationJob creates a new in-memory CredentialRevocationJob.
//
// WithLimit is the only supported option.
func newCredentialRevocationJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*CredentialRevocationJob, error) {
	const op = "vault.newCredentialRevocationJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &CredentialRevocationJob{
		reader: r,
		writer: w,
		kms:    kms,
		limit:  opts.withLimit,
	}, nil
}

// Status returns the current status of the credential revocation job.  Total is the total number
// of credentials that are set to be revoked. Completed is the number of credentials already revoked.
func (r *CredentialRevocationJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.numProcessed,
		Total:     r.numCreds,
	}
}

// Run queries the vault credential repo for credentials that need to be revoked, it then creates
// a vault client and revokes each credential.  Can not be run in parallel, if Run is invoked while
// already running an error with code JobAlreadyRunning will be returned.
func (r *CredentialRevocationJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "vault.(CredentialRevocationJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var creds []*privateCredential
	err := r.reader.SearchWhere(ctx, &creds, "status = ?", []any{RevokeCredential}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numTokens for status report
	r.numProcessed, r.numCreds = 0, len(creds)
	for _, c := range creds {
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		if c.SessionCorrelationId != "" {
			ctx, err = event.NewCorrelationIdContext(ctx, c.SessionCorrelationId)
			if err != nil {
				// log the error, but we should still revoke the credential in Vault since it is
				// no longer being used.
				event.WriteError(ctx, op, err, event.WithInfoMsg("error generating correlation context", "credential id", c.PublicId, "session id", c.SessionId))
			}
		}

		if err := r.revokeCred(ctx, c); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error revoking credential", "credential id", c.PublicId))
		}
		r.numProcessed++
	}

	return nil
}

func (r *CredentialRevocationJob) revokeCred(ctx context.Context, c *privateCredential) error {
	const op = "vault.(CredentialRenewalJob).revokeCred"
	databaseWrapper, err := r.kms.GetWrapper(ctx, c.ProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err = c.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	vc, err := c.client(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	cred := c.toCredential()
	var respErr *vault.ResponseError
	err = vc.revokeLease(ctx, c.ExternalId)
	if ok := errors.As(err, &respErr); ok && respErr.StatusCode == http.StatusBadRequest {
		// Vault returned a 400 when attempting a revoke lease, the lease is already expired.
		// Clobber error and set status to "revoked" below.
		err = nil
	}
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to revoke credential"))
	}

	query, values := cred.updateStatusQuery(RevokedCredential)
	numRows, err := r.writer.Exec(ctx, query, values)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if numRows != 1 {
		return errors.New(ctx, errors.Unknown, op, "credential revoked but failed to update repo")
	}

	return nil
}

// NextRunIn determine when the next credential revocation job should run.
func (r *CredentialRevocationJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return defaultNextRunIn, nil
}

// Name is the unique name of the job.
func (r *CredentialRevocationJob) Name() string {
	return credentialRevocationJobName
}

// Description is the human readable description of the job.
func (r *CredentialRevocationJob) Description() string {
	return "Periodically revokes dynamic credentials that are no longer in use and have been set for revocation (in the revoke state)."
}

// CredentialStoreCleanupJob is the recurring job that deletes Vault credential stores that
// have been soft deleted and tokens have been revoked or expired.
// The CredentialStoreCleanupJob is not thread safe, an attempt to Run the job concurrently
// will result in an JobAlreadyRunning error.
type CredentialStoreCleanupJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	limit        int
	running      ua.Bool
	numProcessed int
	numStores    int
}

// newCredentialStoreCleanupJob creates a new in-memory CredentialStoreCleanupJob.
//
// No options are supported.
func newCredentialStoreCleanupJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*CredentialStoreCleanupJob, error) {
	const op = "vault.newCredentialStoreCleanupJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &CredentialStoreCleanupJob{
		reader: r,
		writer: w,
		kms:    kms,
		limit:  opts.withLimit,
	}, nil
}

// Status returns the current status of the credential store cleanup job.
func (r *CredentialStoreCleanupJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.numProcessed,
		Total:     r.numStores,
	}
}

// Run deletes all vault credential stores in the repo that have been soft deleted.
// Can not be run in parallel, if Run is invoked while already running an error with code
// JobAlreadyRunning will be returned.
func (r *CredentialStoreCleanupJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "vault.(CredentialStoreCleanupJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// TODO (lcr 06/2021): Oplog does not currently support bulk
	// operations. Push cleanup to the database once bulk
	// operations are added.
	var stores []*CredentialStore
	err := r.reader.SearchWhere(ctx, &stores, credStoreCleanupWhereClause, []any{RevokeToken}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numStores for status report
	r.numProcessed, r.numStores = 0, len(stores)
	for _, store := range stores {
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		oplogWrapper, err := r.kms.GetWrapper(ctx, store.ProjectId, kms.KeyPurposeOplog)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to get oplog wrapper for credential store cleanup job", "credential store id", store.PublicId))
			r.numProcessed++
			continue
		}

		_, err = r.writer.Delete(ctx, store, db.WithOplog(oplogWrapper, store.oplog(oplog.OpType_OP_TYPE_DELETE)))
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error deleting credential store", "credential store id", store.PublicId))
		}

		r.numProcessed++
	}

	return nil
}

// NextRunIn determine when the next credential store cleanup job should run.
func (r *CredentialStoreCleanupJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return defaultNextRunIn, nil
}

// Name is the unique name of the job.
func (r *CredentialStoreCleanupJob) Name() string {
	return credentialStoreCleanupJobName
}

// Description is the human readable description of the job.
func (r *CredentialStoreCleanupJob) Description() string {
	return "Periodically deletes Vault credential stores that have been soft deleted and tokens have been revoked or expired."
}

// CredentialCleanupJob is the recurring job that deletes Vault credentials that are no longer
// attached to a session (have a null session_id) and are not active.
// The CredentialCleanupJob is not thread safe, an attempt to Run the job concurrently
// will result in an JobAlreadyRunning error.
type CredentialCleanupJob struct {
	writer db.Writer

	running  ua.Bool
	numCreds int
}

// newCredentialCleanupJob creates a new in-memory CredentialCleanupJob.
//
// No options are supported.
func newCredentialCleanupJob(ctx context.Context, w db.Writer) (*CredentialCleanupJob, error) {
	const op = "vault.newCredentialCleanupJob"
	if w == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	}

	return &CredentialCleanupJob{
		writer: w,
	}, nil
}

// Status returns the current status of the credential cleanup job.
func (r *CredentialCleanupJob) Status() scheduler.JobStatus {
	// Cleanup runs a single exec command to the database, therefore completed and total
	// are both set to numCreds.
	return scheduler.JobStatus{
		Completed: r.numCreds,
		Total:     r.numCreds,
	}
}

// Run deletes all Vault credential in the repo that have a null session_id and are not active.
// Can not be run in parallel, if Run is invoked while already running an error with code
// JobAlreadyRunning will be returned.
func (r *CredentialCleanupJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "vault.(CredentialCleanupJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	numRows, err := r.writer.Exec(ctx, credCleanupQuery, nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	r.numCreds = numRows

	return nil
}

// NextRunIn determine when the next credential cleanup job should run.
func (r *CredentialCleanupJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return defaultNextRunIn, nil
}

// Name is the unique name of the job.
func (r *CredentialCleanupJob) Name() string {
	return credentialCleanupJobName
}

// Description is the human readable description of the job.
func (r *CredentialCleanupJob) Description() string {
	return "Periodically deletes Vault credentials that are no longer attached to a session (have a null session_id) and are not active in Vault."
}
