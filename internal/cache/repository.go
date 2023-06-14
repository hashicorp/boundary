// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	stdErrors "errors"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/seldonio/goven/sql_adaptor"
)

type Repository struct {
	s *Store
}

func NewRepository(ctx context.Context, s *Store) (*Repository, error) {
	const op = "cache.NewRepository"
	switch {
	case util.IsNil(s):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store")
	}
	return &Repository{s: s}, nil
}

func (r *Repository) SaveError(ctx context.Context, resourceType string, err error) error {
	const op = "cache.(Repository).StoreError"
	rw := db.New(r.s.conn)
	apiErr := &ApiError{
		ResourceType: resourceType,
		Error:        err.Error(),
	}
	onConflict := db.OnConflict{
		Target: db.Columns{"token_name", "resource_type"},
		Action: db.SetColumns([]string{"error", "create_time"}),
	}
	if err := rw.Create(ctx, apiErr, db.WithOnConflict(&onConflict)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) RefreshTargets(ctx context.Context, tokenName string, targets []*targets.Target) error {
	const op = "cache.(Repository).RefreshTargets"
	rw := db.New(r.s.conn)
	_, err := rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		if _, err := rw.Exec(ctx, "delete from cache_target where token_name = @token_name", []any{sql.Named("token_name", tokenName)}); err != nil {
			return err
		}
		for _, t := range targets {
			item, err := json.Marshal(t)
			if err != nil {
				return err
			}
			newTarget := Target{
				TokenName:   tokenName,
				Id:          t.Id,
				Name:        t.Name,
				Description: t.Description,
				Address:     t.Address,
				Item:        string(item),
			}
			onConflict := db.OnConflict{
				Target: db.Columns{"token_name", "id"},
				Action: db.SetColumns([]string{"name", "description", "address", "item"}),
			}
			if err := rw.Create(ctx, newTarget, db.WithOnConflict(&onConflict)); err != nil {
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

func (r *Repository) QueryTargets(ctx context.Context, tokenName string, query string) ([]*targets.Target, error) {
	const op = "cache.(Repository).QueryTargets"
	switch {
	case tokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}
	rw := db.New(r.s.conn)
	var cachedTargets []*Target

	reflection := reflect.ValueOf(&Target{})
	defaultFields := sql_adaptor.FieldParseValidatorFromStruct(reflection)
	delete(defaultFields, "item")
	delete(defaultFields, "create_time")
	delete(defaultFields, "token_name")

	matchers := map[*regexp.Regexp]sql_adaptor.ParseValidateFunc{}
	fieldMappings := map[string]string{}
	queryAdaptor := sql_adaptor.NewSqlAdaptor(fieldMappings, defaultFields, matchers)

	parsedQuery, err := queryAdaptor.Parse(query)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if err := rw.SearchWhere(ctx, &cachedTargets, parsedQuery.Raw, sql_adaptor.StringSliceToInterfaceSlice(parsedQuery.Values), db.WithLimit(-1)); err != nil {
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

func (r *Repository) FindTargets(ctx context.Context, tokenName string, opt ...Option) ([]*targets.Target, error) {
	const op = "cache.(Repository).FindTargets"
	switch {
	case tokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	}
	rw := db.New(r.s.conn)
	var cachedTargets []*Target

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	whereClause := []string{"token_name = @token_name"}
	whereParameters := []any{sql.Named("token_name", tokenName)}

	if opts.withIdContains != "" {
		whereClause = append(whereClause, "id like @contains_id")
		whereParameters = append(whereParameters, sql.Named("contains_id", "%"+opts.withIdContains+"%"))
	}
	if opts.withNameContains != "" {
		whereClause = append(whereClause, "name like @contains_name")
		whereParameters = append(whereParameters, sql.Named("contains_name", "%"+opts.withNameContains+"%"))
	}
	if opts.withDescriptionContains != "" {
		whereClause = append(whereClause, "description like @contains_description")
		whereParameters = append(whereParameters, sql.Named("contains_description", "%"+opts.withDescriptionContains+"%"))
	}
	if opts.withAddressContains != "" {
		whereClause = append(whereClause, "address like @contains_address")
		whereParameters = append(whereParameters, sql.Named("contains_address", "%"+opts.withAddressContains+"%"))
	}

	if opts.withIdStartsWith != "" {
		whereClause = append(whereClause, "id like @starts_with_id")
		whereParameters = append(whereParameters, sql.Named("starts_with_id", opts.withIdStartsWith+"%"))
	}
	if opts.withNameStartsWith != "" {
		whereClause = append(whereClause, "name like @starts_with_name")
		whereParameters = append(whereParameters, sql.Named("starts_with_name", opts.withNameStartsWith+"%"))
	}
	if opts.withDescriptionStartsWith != "" {
		whereClause = append(whereClause, "description like @starts_with_description")
		whereParameters = append(whereParameters, sql.Named("starts_with_description", opts.withDescriptionStartsWith+"%"))
	}
	if opts.withAddressStartsWith != "" {
		whereClause = append(whereClause, "address like @starts_with_address")
		whereParameters = append(whereParameters, sql.Named("starts_with_address", opts.withAddressStartsWith+"%"))
	}

	if opts.withIdEndsWith != "" {
		whereClause = append(whereClause, "id like @ends_with_id")
		whereParameters = append(whereParameters, sql.Named("ends_with_id", "%"+opts.withIdEndsWith))
	}
	if opts.withNameEndsWith != "" {
		whereClause = append(whereClause, "name like @ends_with_name")
		whereParameters = append(whereParameters, sql.Named("ends_with_name", "%"+opts.withNameEndsWith))
	}
	if opts.withDescriptionEndsWith != "" {
		whereClause = append(whereClause, "description like @ends_with_description")
		whereParameters = append(whereParameters, sql.Named("ends_with_description", "%"+opts.withDescriptionEndsWith))
	}
	if opts.withAddressEndsWith != "" {
		whereClause = append(whereClause, "address like @ends_with_address")
		whereParameters = append(whereParameters, sql.Named("ends_with_address", "%"+opts.withAddressEndsWith))
	}

	if err := rw.SearchWhere(ctx, &cachedTargets, strings.Join(whereClause, " and "), whereParameters, db.WithLimit(-1)); err != nil {
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
	TokenName   string `gorm:"primaryKey"`
	Id          string `gorm:"primaryKey"`
	Name        string
	Description string
	Address     string
	Item        string
	CreatedTime time.Time
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
