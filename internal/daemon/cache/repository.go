// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	stdErrors "errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/mql"
)

const (
	personaLimit          = 50
	personaStalenessLimit = 36 * time.Hour
)

// tokenLookupFn takes a token name and returns the token
type tokenLookupFn func(keyring string, tokenName string) *authtokens.AuthToken

type Repository struct {
	rw            *db.Db
	tokenLookupFn tokenLookupFn
}

func NewRepository(ctx context.Context, s *Store, tFn tokenLookupFn, opt ...Option) (*Repository, error) {
	const op = "cache.NewRepository"
	switch {
	case util.IsNil(s):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store")
	case util.IsNil(tFn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token lookup function")
	}

	return &Repository{rw: db.New(s.conn), tokenLookupFn: tFn}, nil
}

func (r *Repository) SaveError(ctx context.Context, resourceType string, err error) error {
	const op = "cache.(Repository).StoreError"
	switch {
	case resourceType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "resource type is empty")
	case err == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "error is nil")
	}
	apiErr := &ApiError{
		ResourceType: resourceType,
		Error:        err.Error(),
	}
	onConflict := db.OnConflict{
		Target: db.Columns{"token_name", "resource_type"},
		Action: db.SetColumns([]string{"error", "create_time"}),
	}
	if err := r.rw.Create(ctx, apiErr, db.WithOnConflict(&onConflict)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) refreshCachedTargets(ctx context.Context, p *Persona, targets []*targets.Target) error {
	const op = "cache.(Repository).refreshTargets"
	switch {
	case util.IsNil(p):
		return errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case p.UserId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}

	foundP := p.clone()
	if err := r.rw.LookupById(ctx, foundP); err != nil {
		// if this persona isn't known, error out.
		return errors.Wrap(ctx, err, op, errors.WithMsg("looking up persona"))
	}

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		// TODO: Instead of deleting everything, use refresh tokens and apply the delta
		if _, err := w.Exec(ctx, "delete from cache_target where boundary_addr = @boundary_addr and token_name = @token_name and keyring_type = @keyring_type and boundary_user_id = @boundary_user_id",
			[]any{sql.Named("boundary_addr", foundP.BoundaryAddr), sql.Named("keyring_type", foundP.KeyringType), sql.Named("token_name", foundP.TokenName), sql.Named("boundary_user_id", foundP.UserId)}); err != nil {
			return err
		}

		for _, t := range targets {
			item, err := json.Marshal(t)
			if err != nil {
				return err
			}
			newTarget := Target{
				BoundaryAddr:   foundP.BoundaryAddr,
				KeyringType:    foundP.KeyringType,
				TokenName:      foundP.TokenName,
				BoundaryUserId: foundP.UserId,
				Id:             t.Id,
				Name:           t.Name,
				Description:    t.Description,
				Address:        t.Address,
				Item:           string(item),
			}
			onConflict := db.OnConflict{
				Target: db.Columns{"boundary_addr", "token_name", "keyring_type", "boundary_user_id", "id"},
				Action: db.UpdateAll(true),
			}
			if err := w.Create(ctx, newTarget, db.WithOnConflict(&onConflict)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if saveErr := r.SaveError(ctx, resource.Target.String(), err); saveErr != nil {
			return stdErrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) ListTargets(ctx context.Context, p *Persona) ([]*targets.Target, error) {
	const op = "cache.(Repository).ListTargets"
	switch {
	case util.IsNil(p):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case p.UserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}
	ret, err := r.searchTargets(ctx, p, "true", nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) QueryTargets(ctx context.Context, p *Persona, query string) ([]*targets.Target, error) {
	const op = "cache.(Repository).QueryTargets"
	switch {
	case util.IsNil(p):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case p.UserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}

	w, err := mql.Parse(query, Target{}, mql.WithIgnoredFields("BoundaryAddr", "KeyringType", "TokenName", "BoundaryUserId", "Item"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	ret, err := r.searchTargets(ctx, p, w.Condition, w.Args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchTargets(ctx context.Context, p *Persona, condition string, searchArgs []any) ([]*targets.Target, error) {
	const op = "cache.(Repository).searchTargets"
	switch {
	case p == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is missing")
	case p.UserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case condition == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "condition is missing")
	}

	condition = fmt.Sprintf("%s and ((keyring_type, token_name, boundary_addr, boundary_user_id) = (?, ?, ?, ?))", condition)
	args := append(searchArgs, p.KeyringType, p.TokenName, p.BoundaryAddr, p.UserId)
	var cachedTargets []*Target
	if err := r.rw.SearchWhere(ctx, &cachedTargets, condition, args, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	retTargets := make([]*targets.Target, 0, len(cachedTargets))
	for _, cachedTar := range cachedTargets {
		var tar targets.Target
		if err := json.Unmarshal([]byte(cachedTar.Item), &tar); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		retTargets = append(retTargets, &tar)
	}
	return retTargets, nil
}

type Target struct {
	BoundaryAddr   string `gorm:"primaryKey"`
	KeyringType    string `gorm:"primaryKey"`
	TokenName      string `gorm:"primaryKey"`
	BoundaryUserId string `gorm:"primaryKey"`
	Id             string `gorm:"primaryKey"`
	Name           string
	Description    string
	Address        string
	Item           string
}

func (*Target) TableName() string {
	return "cache_target"
}

type ApiError struct {
	TokenName    string `gorm:"primaryKey"`
	ResourceType string `gorm:"primaryKey"`
	Error        string
	CreateTime   time.Time
}

func (*ApiError) TableName() string {
	return "cache_api_error"
}
