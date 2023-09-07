// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"golang.org/x/exp/maps"
)

// AddPersona adds a persona to the repository.  If the token in the
// keyring doesn't match the id provided an error is returned.  If the number of
// personas now exceed a limit, the persona retrieved least recently is deleted.
func (r *Repository) AddPersona(ctx context.Context, bAddr, tokenName, keyringType, authTokId string, opt ...Option) error {
	const op = "cache.(Repository).AddPersona"
	switch {
	case tokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is empty")
	case keyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "keyring type is empty")
	case bAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is empty")
	case authTokId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary auth token id is empty")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var at *authtokens.AuthToken
	switch keyringType {
	case base.NoneKeyring:
		if tokenName != authTokId {
			return errors.New(ctx, errors.InvalidParameter, op, "when using none keyring type token name must match the auth token id")
		}

		if opts.withAuthToken == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "when using none keyring WithAuthToken must be used")
		}

		if !strings.HasPrefix(opts.withAuthToken, authTokId) {
			return errors.New(ctx, errors.InvalidParameter, op, "boundary auth token id doesn't match the provided auth token")
		}
		at, err = r.tokenReadFn(ctx, bAddr, opts.withAuthToken)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get auth token info for provided auth token"))
		}
		r.tokIdToTok[authTokId] = opts.withAuthToken
	default:
		at = r.tokenKeyringFn(keyringType, tokenName)
	}

	if at == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "unable to find token in the keyring specified")
	}
	if authTokId != at.Id {
		return errors.New(ctx, errors.InvalidParameter, op, "provided auth token id doesn't match the one stored")
	}

	// Even though the auth token is already stored, we still call create so
	// the last accessed timestamps can get updated since calling this method
	// indicates that the token was used and is still valid.
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		st := &Persona{
			KeyringType:      keyringType,
			TokenName:        tokenName,
			BoundaryAddr:     bAddr,
			UserId:           at.UserId,
			AuthTokenId:      at.Id,
			LastAccessedTime: time.Now(),
		}
		onConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id", "boundary_addr", "user_id", "last_accessed_time"}),
		}
		if err := writer.Create(ctx, st, db.WithOnConflict(onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		personas, err := listPersonas(ctx, reader)
		if err != nil {
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
			if _, err := deletePersona(ctx, writer, oldestPersona); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err := r.cleanKeyringlessAuthTokens(ctx, reader); err != nil {
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

// LookupPersona returns the Persona in the cache if one exists.
// Accepts withUpdateLastAccessedTime, WithAuthTokenId, and WithBoundaryAddress
// options.  If withUpdateLastAccessedTime is provided, the last update time
// of the returned persona will be updated to the current time and reflected
// in the db. The returned Persona will not have the updated time.
// If WithAuthTokenId or WithBoundaryAddress are provided the returned Persona
// must have the matching AuthTokenId or BoundaryAddr respectively.
func (r *Repository) LookupPersona(ctx context.Context, tokenName, keyringType string, opt ...Option) (*Persona, error) {
	const op = "cache.(Repository).lookupStoredAuthToken"
	switch {
	case keyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is empty")
	case tokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is empty")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	p := &Persona{
		KeyringType: keyringType,
		TokenName:   tokenName,
	}
	if err := r.rw.LookupById(ctx, p); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}

	if opts.withBoundaryAddress != "" && opts.withBoundaryAddress != p.BoundaryAddr {
		// If we found a persona that doesn't have the provided address it
		// is not the correct one, so the return should indicate the looked up
		// persona could not be found.
		return nil, nil
	}

	if opts.withAuthTokenId != "" && opts.withAuthTokenId != p.AuthTokenId {
		// If we found a persona that doesn't have the provided auth token id
		// is not the correct one, so the return should indicate the looked up
		// persona could not be found.
		return nil, nil
	}

	if opts.withUpdateLastAccessedTime {
		updatedP := &Persona{
			BoundaryAddr:     p.BoundaryAddr,
			TokenName:        p.TokenName,
			KeyringType:      p.KeyringType,
			LastAccessedTime: time.Now(),
		}
		if _, err := r.rw.Update(ctx, updatedP, []string{"LastAccessedTime"}, nil); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return p, nil
}

// deletePersona deletes a persona
func (r *Repository) deletePersona(ctx context.Context, p *Persona) (retErr error) {
	const op = "cache.(Repository).deletePersona"
	switch {
	case p == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing persona")
	case p.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing token name")
	case p.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing keyring type")
	}

	n, err := deletePersona(ctx, r.rw, p)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if err := r.cleanKeyringlessAuthTokens(ctx, r.rw); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	switch n {
	case 1:
		return nil
	case 0:
		return errors.New(ctx, errors.RecordNotFound, op, "persona not found when attempting deletion")
	default:
		return errors.New(ctx, errors.MultipleRecords, op, "multiple personas deleted when one was requested")
	}
}

// removeStalePersonas removes all personas which are older than the staleness
func (r *Repository) removeStalePersonas(ctx context.Context, opt ...Option) error {
	const op = "cache.(Repository).removeStalePersonas"
	if _, err := r.rw.Exec(ctx, "delete from cache_persona where last_accessed_time < @last_accessed_time",
		[]any{sql.Named("last_accessed_time", time.Now().Add(-personaStalenessLimit))}); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := r.cleanKeyringlessAuthTokens(ctx, r.rw); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// listPersonas returns all known personas in the cache
func (r *Repository) listPersonas(ctx context.Context) ([]*Persona, error) {
	const op = "cache.(Repository).listPersonas"
	p, err := listPersonas(ctx, r.rw)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return p, nil
}

func (r *Repository) cleanKeyringlessAuthTokens(ctx context.Context, reader db.Reader) error {
	const op = "cache.(Repository).cleanKeyringlessAuthTokens"
	ps, err := listPersonas(ctx, reader)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	personaAuthTokenIds := make(map[string]struct{})
	for _, p := range ps {
		personaAuthTokenIds[p.AuthTokenId] = struct{}{}
	}
	maps.DeleteFunc(r.tokIdToTok, func(k, _ string) bool {
		_, ok := personaAuthTokenIds[k]
		return !ok
	})
	return nil
}

func listPersonas(ctx context.Context, reader db.Reader) ([]*Persona, error) {
	const op = "cache.listPersonas"
	var ps []*Persona
	if err := reader.SearchWhere(ctx, &ps, "", []any{}, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ps, nil
}

// deleteToken executes a delete command using the provided db.Writer for the provided persona.
func deletePersona(ctx context.Context, w db.Writer, st *Persona) (int, error) {
	const op = "cache.deletePersona"
	switch {
	case util.IsNil(w):
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case util.IsNil(st):
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	}
	// TODO(https://github.com/go-gorm/gorm/issues/4879): Use the
	//   writer.Delete() function once the gorm bug is fixed. Until then
	//   the gorm driver for sqlite has an error which wont execute a
	//   delete correctly. as a work around we manually execute the
	//   query here.
	n, err := w.Exec(ctx, "delete from cache_persona where (keyring_type, token_name) in (values (?, ?))",
		[]any{st.KeyringType, st.TokenName})
	if err != nil {
		err = errors.Wrap(ctx, err, op)
	}
	return n, err
}

type Persona struct {
	KeyringType      string `gorm:"primaryKey"`
	TokenName        string `gorm:"primaryKey"`
	BoundaryAddr     string
	UserId           string
	AuthTokenId      string
	LastAccessedTime time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
}

func (*Persona) TableName() string {
	return "cache_persona"
}

func (p *Persona) clone() *Persona {
	return &Persona{
		KeyringType:      p.KeyringType,
		TokenName:        p.TokenName,
		BoundaryAddr:     p.BoundaryAddr,
		UserId:           p.UserId,
		AuthTokenId:      p.AuthTokenId,
		LastAccessedTime: p.LastAccessedTime,
	}
}
