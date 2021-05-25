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
)

const (
	defaultTokenRenewalInterval = 5 * time.Minute
	tokenRenewalWindow          = 10 * time.Minute
)

// TokenRenewalJob is the recurring job that renews credential store Vault tokens that
// are in the `current` and `maintaining` state
type TokenRenewalJob struct {
	repoFn RepositoryFactory
	logger hclog.Logger
	limit  int

	numTokens, numProcessed int
}

// renewablePrivateStore provides a simple way to read an Vault Tokens that need to be renewed.
// By definition, it's used only for reading tokens.
type renewablePrivateStore struct {
	Store       *privateStore `gorm:"embedded"`
	RenewalTime *timestamp.Timestamp
}

// TableName returns the table name for gorm.
func (_ *renewablePrivateStore) TableName() string {
	return "credential_vault_job_renewable_client_private"
}

func NewTokenRenewalJob(repoFn RepositoryFactory, logger hclog.Logger, opt ...Option) (*TokenRenewalJob, error) {
	const op = "vault.NewTokenRenewalJob"
	if repoFn == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing vault credential repo function")
	}
	if logger == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing logger")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &TokenRenewalJob{
		repoFn: repoFn,
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
// a vault client and renews each token.
func (r *TokenRenewalJob) Run(ctx context.Context) error {
	const op = "vault.(TokenRenewalJob).Run"

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, op)
	}

	repo, err := r.repoFn()
	if err != nil {
		return errors.Wrap(err, op)
	}

	var rps []*renewablePrivateStore
	// Fetch all tokens that will reach their renewal point within the tokenRenewalWindow.
	// This is done to avoid constantly scheduling the token renewal job when there are multiple tokens
	// set to renew in sequence.
	err = repo.reader.SearchWhere(ctx, &rps, `renewal_time < wt_add_seconds_to_now(?)`, []interface{}{tokenRenewalWindow.Seconds()}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(err, op)
	}

	// Set numTokens for status report
	r.numTokens = len(rps)

	for _, s := range rps {
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(err, op)
		}

		err := r.renewToken(ctx, repo, s)
		if err != nil {
			r.logger.Error("error renewing token", "credential store id", s.Store.StoreId, "token status", s.Store.TokenStatus)
		}

		r.numProcessed++
	}

	return nil
}

func (r *TokenRenewalJob) renewToken(ctx context.Context, repo *Repository, s *renewablePrivateStore) error {
	const op = "vault.(TokenRenewalJob).renewToken"
	databaseWrapper, err := repo.kms.GetWrapper(ctx, s.Store.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	err = s.Store.decrypt(ctx, databaseWrapper)
	if err != nil {
		return errors.Wrap(err, op)
	}

	vc, err := s.Store.client()
	if err != nil {
		return errors.Wrap(err, op)
	}

	var respErr *vault.ResponseError
	renewedToken, err := vc.renewToken()
	if ok := errors.As(err, &respErr); ok && respErr.StatusCode == http.StatusForbidden {
		// Vault returned a 403 when attempting a renew self, the token is either expired
		// or malformed.  Set status to "expired" so credentials created with token can be
		// cleaned up.
		numRows, err := repo.writer.Exec(ctx, updateTokenStatusQuery, []interface{}{StatusExpired, s.Store.TokenHmac})
		if err != nil {
			return errors.Wrap(err, op)
		}
		if numRows != 1 {
			return errors.New(errors.Unknown, op, "token expired but failed to update repo")
		}
		r.logger.Info("Vault credential store token has expired", "credential store id", s.Store.StoreId, "previous status", s.Store.TokenStatus)

		return nil
	}
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to renew vault token"))
	}

	tokenExpires, err := renewedToken.TokenTTL()
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get vault token expiration"))
	}

	exp := int(tokenExpires.Round(time.Second).Seconds())
	numRows, err := repo.writer.Exec(ctx, updateTokenExpirationQuery, []interface{}{exp, s.Store.TokenHmac})
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
	repo, err := r.repoFn()
	if err != nil {
		return defaultTokenRenewalInterval, errors.Wrap(err, op)
	}

	rows, err := repo.reader.Query(context.Background(), tokenRenewalNextRunInQuery, nil)
	if err != nil {
		return defaultTokenRenewalInterval, errors.Wrap(err, op)
	}
	defer rows.Close()

	for rows.Next() {
		type NextRenewal struct {
			RenewalIn time.Duration
		}
		var n NextRenewal
		err = repo.reader.ScanRows(rows, &n)
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
	return "vault_token_renewal"
}

// Description is the human readable description of the job.
func (r *TokenRenewalJob) Description() string {
	return "Periodically renews Vault credential store tokens that are in a maintaining or current state."
}
