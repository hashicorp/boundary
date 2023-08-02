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

const personaLimit = 50

type Repository struct {
	rw *db.Db
}

func NewRepository(ctx context.Context, s *Store) (*Repository, error) {
	const op = "cache.NewRepository"
	switch {
	case util.IsNil(s):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store")
	}
	return &Repository{rw: db.New(s.conn)}, nil
}

// AddPersona adds a persona to the repository.  If the number of personas now
// exceed a limit, the  persona retrieved least recently is deleted.
func (r *Repository) AddPersona(ctx context.Context, p *Persona) error {
	const op = "cache.(Repository).AddPersona"
	switch {
	case p == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "persona's token name is empty")
	case p.BoundaryAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "persona's boundary address is empty")
	}

	onConflict := db.OnConflict{
		Target: db.Columns{"boundary_addr", "token_name"},
		Action: db.SetColumns([]string{"auth_token_id", "last_accessed_time"}),
	}
	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		if err := writer.Create(ctx, p, db.WithOnConflict(&onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		var personas []*Persona
		if err := reader.SearchWhere(ctx, &personas, "", []any{}, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if len(personas) <= personaLimit {
			return nil
		}

		var oldestPersona *Persona
		for _, p := range personas {
			if oldestPersona == nil || oldestPersona.LastAccessedTime.After(p.LastAccessedTime) {
				oldestPersona = p
			}
		}
		if oldestPersona != nil {
			if _, err := writer.Delete(ctx, oldestPersona); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// LookupPersona returns the persona and updates its last accessed time
func (r *Repository) LookupPersona(ctx context.Context, addr string, tokenName string) (*Persona, error) {
	const op = "cache.(Repository).LookupPersona"
	switch {
	case addr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "address is empty")
	case tokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is empty")
	}

	p := &Persona{
		BoundaryAddr: addr,
		TokenName:    tokenName,
	}
	if err := r.rw.LookupById(ctx, p); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	updatedP := &Persona{
		BoundaryAddr:     p.BoundaryAddr,
		TokenName:        p.TokenName,
		LastAccessedTime: time.Now(),
	}
	if _, err := r.rw.Update(ctx, updatedP, []string{"LastAccessedTime"}, nil); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return updatedP, nil
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

func (r *Repository) RefreshTargets(ctx context.Context, p *Persona, targets []*targets.Target) error {
	const op = "cache.(Repository).RefreshTargets"
	switch {
	case p == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.BoundaryAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	}

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		// TODO: Instead of deleting everything, use refresh tokens and apply the delta
		if _, err := w.Exec(ctx, "delete from cache_target where boundary_addr = @boundary_addr and token_name = @token_name",
			[]any{sql.Named("boundary_addr", p.BoundaryAddr), sql.Named("token_name", p.TokenName)}); err != nil {
			return err
		}

		for _, t := range targets {
			item, err := json.Marshal(t)
			if err != nil {
				return err
			}
			newTarget := Target{
				BoundaryAddr: p.BoundaryAddr,
				TokenName:    p.TokenName,
				Id:           t.Id,
				Name:         t.Name,
				Description:  t.Description,
				Address:      t.Address,
				Item:         string(item),
			}
			onConflict := db.OnConflict{
				Target: db.Columns{"boundary_addr", "token_name", "id"},
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

func (r *Repository) QueryTargets(ctx context.Context, p *Persona, query string) ([]*targets.Target, error) {
	const op = "cache.(Repository).QueryTargets"
	switch {
	case p == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is missing")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}
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
	if err := r.rw.SearchWhere(ctx, &cachedTargets, parsedQuery.Raw, sql_adaptor.StringSliceToInterfaceSlice(parsedQuery.Values), db.WithLimit(-1)); err != nil {
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

func (r *Repository) FindTargets(ctx context.Context, p *Persona, opt ...Option) ([]*targets.Target, error) {
	const op = "cache.(Repository).FindTargets"
	switch {
	case p == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is missing")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	}
	var cachedTargets []*Target

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	whereClause := []string{"boundary_addr = @boundary_addr and token_name = @token_name"}
	whereParameters := []any{sql.Named("boundary_addr", p.BoundaryAddr), sql.Named("token_name", p.TokenName)}

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

	if err := r.rw.SearchWhere(ctx, &cachedTargets, strings.Join(whereClause, " and "), whereParameters, db.WithLimit(-1)); err != nil {
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
	BoundaryAddr string `gorm:"primaryKey"`
	TokenName    string `gorm:"primaryKey"`
	Id           string `gorm:"primaryKey"`
	Name         string
	Description  string
	Address      string
	Item         string
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

type Persona struct {
	BoundaryAddr     string `gorm:"primaryKey"`
	TokenName        string `gorm:"primaryKey"`
	AuthTokenId      string
	LastAccessedTime time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
}

func (*Persona) TableName() string {
	return "cache_persona"
}
