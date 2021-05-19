package vault

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
	"google.golang.org/protobuf/proto"
)

const (
	defaultTokenRenewalInterval = time.Minute * 5
	tokenRenewalWindow          = 10 // in minutes
)

type TokenRenewalJob struct {
	repoFn RepositoryFactory
	logger hclog.Logger
	limit  int

	numTokens, numProcessed int
}

// tokenRenewalView provides a simple way to read an Vault Tokens that need to be renewed.
// By definition, it's used only for reading tokens.
type tokenRenewalView struct {
	*store.Token
	tableName string
}

// TableName returns the view name.
func (a *tokenRenewalView) TableName() string {
	return "credential_vault_job_renewable_tokens"
}

func (t *tokenRenewalView) toToken() *Token {
	cp := proto.Clone(t.Token)
	return &Token{
		Token: cp.(*store.Token),
	}
}

func NewTokenRenewalJob(repoFn RepositoryFactory, logger hclog.Logger, opt ...Option) (*TokenRenewalJob, error) {
	const op = "vault.NewNewTokenRenewal"
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

	var tokens []*tokenRenewalView
	err = repo.reader.SearchWhere(ctx, &tokens, `now() + (?||'min')::interval > renewal_time`, []interface{}{tokenRenewalWindow}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(err, op)
	}

	// Set numTokens for status report
	r.numTokens = len(tokens)

	// Create credential store cache to avoid repeated repo calls
	credStores := new(sync.Map)
	for _, t := range tokens {
		// Verify context is not done before renewing next token
		if err := ctx.Err(); err != nil {
			return errors.Wrap(err, op)
		}

		if err := r.renewToken(ctx, t.toToken(), credStores); err != nil {
			return errors.Wrap(err, op)
		}
		r.numProcessed++
	}

	return nil
}

func (r *TokenRenewalJob) renewToken(ctx context.Context, t *Token, credStores *sync.Map) error {
	const op = "vault.(TokenRenewalJob).renewToken"
	repo, err := r.repoFn()
	if err != nil {
		return errors.Wrap(err, op)
	}

	var pcs *privateCredentialStore
	if s, ok := credStores.Load(t.StoreId); ok {
		pcs = s.(*privateCredentialStore)
	} else {
		// credential store not found in cache, lookup in repo
		pcs, err = repo.lookupPrivateCredentialStore(ctx, t.StoreId)
		if err != nil {
			return errors.Wrap(err, op, errors.WithMsg("unable to get credential store"))
		}
		credStores.Store(t.StoreId, pcs)
	}

	databaseWrapper, err := repo.kms.GetWrapper(ctx, pcs.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	if err := t.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(err, op, errors.WithMsg("failed to decrypt token"))
	}

	vc, err := pcs.client()
	if err != nil {
		return errors.Wrap(err, op)
	}
	vc.SwapToken(string(t.Token.Token))

	var respErr *vault.ResponseError
	renewedToken, err := vc.RenewToken()
	if ok := errors.As(err, &respErr); ok && respErr.StatusCode == http.StatusForbidden {
		// Vault returned a 403 when attempting a renew self, the token is either expired
		// or malformed.  Set status to "expired" so credentials created with token can be
		// cleaned up.
		numRows, err := repo.writer.Exec(ctx, updateTokenStatusQuery, []interface{}{StatusExpired, t.TokenHmac})
		if err != nil {
			return errors.Wrap(err, op)
		}
		if numRows != 1 {
			return errors.New(errors.Unknown, op, "token expired but failed to update repo")
		}
		r.logger.Info("Vault credential store token has expired", "credential store id", t.StoreId, "token hmac", t.TokenHmac)

		// TODO add oplog
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
	numRows, err := repo.writer.Exec(ctx, updateTokenExpirationQuery, []interface{}{exp, t.TokenHmac})
	if err != nil {
		return errors.Wrap(err, op)
	}
	if numRows != 1 {
		return errors.New(errors.Unknown, op, "token renewed but failed to update repo")
	}

	// TODO add oplog

	return nil
}

// NextRunIn queries the vault credential repo to determine when the next token renewal job should run.
func (r *TokenRenewalJob) NextRunIn() time.Duration {
	repo, err := r.repoFn()
	if err != nil {
		r.logger.Error("Error generating repository for Vault token renewal next run check", "error", err)
		return defaultTokenRenewalInterval
	}

	rows, err := repo.reader.Query(context.Background(), tokenRenewalNextRunInQuery, nil)
	if err != nil {
		r.logger.Error("Error querying repository for Vault token renewal next run check", "error", err)
		return defaultTokenRenewalInterval
	}
	defer rows.Close()

	for rows.Next() {
		type NextRenewal struct {
			Now         time.Time
			RenewalTime time.Time
		}
		var n NextRenewal
		err = repo.reader.ScanRows(rows, &n)
		if err != nil {
			r.logger.Error("Error scanning rows for Vault token renewal next run check", "error", err)
			return defaultTokenRenewalInterval
		}
		return n.RenewalTime.Sub(n.Now)
	}

	return defaultTokenRenewalInterval
}

// Name is the unique name of the job.
func (r *TokenRenewalJob) Name() string {
	return "vault_token_renewal"
}

// Description is the human readable description of the job.
func (r *TokenRenewalJob) Description() string {
	return "Periodically renews Vault credential store tokens that are in a maintaining or current state."
}
