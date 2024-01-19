// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// LookupAppToken will lookup an app token in the repo, along with its
// associated value objects. If it's not found, it will return nil, nil.  The
// withReader option is supported so callers from create and update can
// specify a reader to use.
func (r *Repository) LookupAppToken(ctx context.Context, appTokenId string, opt ...Option) (*AppToken, error) {
	const op = "apptoken.(Repository).LookupAppToken"
	switch {
	case appTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token id")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if opts.withReader == nil {
		// might as well specify a reader, since we're not being used in the
		// context of pagination and/or refresh.
		opt = append(opt, withReader(ctx, r.reader))
	}

	tks, _, err := r.queryAppTokens(ctx, lookupAppTokenTemplate, []any{sql.Named("public_id", appTokenId)}, opt...)
	switch {
	case err != nil:
		return nil, errors.Wrap(ctx, err, op)
	case len(tks) == 0:
		return nil, nil // not an error to return no rows for a "lookup"
	case len(tks) > 1:
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("%s matched more than one app token ", appTokenId))
	default:
		return tks[0], nil
	}
}

// appTokenAgg is a view that aggregates the app token and it's value objects.
type appTokenAgg struct {
	PublicId                       string `gorm:"primary_key"`
	CreateTime                     *timestamp.Timestamp
	ExpirationTime                 *timestamp.Timestamp
	CreatedBy                      string
	ExpirationIntervalInMaxSeconds uint32
	Name                           string
	Description                    string
	ScopeId                        string
	CanonicalGrants                string
	RawGrants                      string
}

// TableName returns the table name for gorm
func (agg *appTokenAgg) TableName() string { return "app_token_agg" }

// queryAppTokens allows callers to search for app tokens.  The query specified
// must end with "limit %d" and the limit will be applied to the query (either
// the default or a specified limit in the options).
// Supported options: WithLimit, withReader
func (r *Repository) queryAppTokens(ctx context.Context, query string, args []any, opt ...Option) ([]*AppToken, time.Time, error) {
	const op = "apptoken.queryAppTokens"
	switch {
	case query == "":
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing query")
	case !strings.HasSuffix(strings.ToLower(strings.TrimSpace(query)), "limit %d"):
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "query ("+query+" must end with 'limit %%d'")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	query = fmt.Sprintf(query, limit)

	var aggTokens []*appTokenAgg
	var transactionTime time.Time
	switch {
	case opts.withReader != nil:
		rows, err := opts.withReader.Query(ctx, query, args)
		if err != nil {
			return nil, time.Time{}, errors.Wrap(ctx, err, op)
		}
		for rows.Next() {
			var agg appTokenAgg
			if err := opts.withReader.ScanRows(ctx, rows, &agg); err != nil {
				return nil, time.Time{}, errors.Wrap(ctx, err, op)
			}
			aggTokens = append(aggTokens, &agg)
		}
		if err := rows.Err(); err != nil {
			return nil, time.Time{}, errors.Wrap(ctx, err, op)
		}
		// no need to set a transaction time, since we're not using a writer
		// within a transaction.
	default:
		if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
			var err error
			rows, err := rd.Query(ctx, query, args)
			if err != nil {
				return err
			}
			for rows.Next() {
				var agg appTokenAgg
				if err := rd.ScanRows(ctx, rows, &agg); err != nil {
					return err
				}
				aggTokens = append(aggTokens, &agg)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			transactionTime, err = rd.Now(ctx)
			return err
		}); err != nil {
			return nil, time.Time{}, errors.Wrap(ctx, err, op)
		}
	}
	var tokens []*AppToken
	for _, agg := range aggTokens {
		tk, err := aggToTk(ctx, agg)
		if err != nil {
			return nil, time.Time{}, errors.Wrap(ctx, err, op)
		}
		tokens = append(tokens, tk)
	}
	return tokens, transactionTime, nil
}

func aggToTk(ctx context.Context, agg *appTokenAgg) (*AppToken, error) {
	const op = "apptoken.aggToTk"
	tk := AllocAppToken()
	tk.PublicId = agg.PublicId
	tk.ScopeId = agg.ScopeId
	tk.ExpirationIntervalInMaxSeconds = agg.ExpirationIntervalInMaxSeconds
	tk.CreatedBy = agg.CreatedBy
	tk.Name = agg.Name
	tk.Description = agg.Description
	tk.CreateTime = agg.CreateTime
	tk.ExpirationTime = agg.ExpirationTime
	if agg.CanonicalGrants != "" {
		canonical := strings.Split(agg.CanonicalGrants, "|")
		raw := strings.Split(agg.RawGrants, "|")
		if len(canonical) != len(raw) {
			return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("canonical (%d) and raw grants (%d) are not the same len", len(canonical), len(raw)))
		}
		grants := make([]*store.AppTokenGrant, 0, len(canonical))
		for i := 0; i < len(canonical); i++ {
			ag := AllocAppTokenGrant()
			ag.AppTokenId = tk.PublicId
			ag.CanonicalGrant = canonical[i]
			ag.RawGrant = raw[0]
			ag.CreateTime = tk.CreateTime
			grants = append(grants, ag.AppTokenGrant)
		}
		tk.Grants = grants
	}
	return tk, nil
}
