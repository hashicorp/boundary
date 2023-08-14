// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

type tokenReader interface {
	ReadTokenFromKeyring(string, string) *authtokens.AuthToken
}

type refresher interface {
	refresh()
}

type personaToAdd struct {
	KeyringType  string
	TokenName    string
	BoundaryAddr string
	AuthTokenId  string
}

func (p *personaToAdd) toPersona() *cache.Persona {
	if p == nil {
		return nil
	}
	return &cache.Persona{
		KeyringType:  p.KeyringType,
		TokenName:    p.TokenName,
		BoundaryAddr: p.BoundaryAddr,
		AuthTokenId:  p.AuthTokenId,
	}
}

func newPersonaHandlerFunc(ctx context.Context, store *cache.Store, atReader tokenReader, refresher refresher) (http.HandlerFunc, error) {
	const op = "daemon.newPersonaHandlerFunc"
	switch {
	case util.IsNil(store):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "store is nil")
	case util.IsNil(atReader):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "tokenReader is nil")
	case util.IsNil(refresher):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refresher is nil")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != http.MethodPost {
			writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var perReq personaToAdd

		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, "unable to read request body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(data, &perReq); err != nil {
			writeError(w, "unable to parse request body", http.StatusBadRequest)
			return
		}

		switch {
		case perReq.TokenName == "":
			writeError(w, "TokenName is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.KeyringType == "":
			writeError(w, "KeyringType is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.BoundaryAddr == "":
			writeError(w, "BoundaryAddr is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.AuthTokenId == "":
			writeError(w, "AuthTokenId is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.KeyringType == base.NoneKeyring:
			// TODO: Support personas that have tokens not stored in a keyring
			writeError(w, fmt.Sprintf("KeyringType is set to %s which is not supported", perReq.KeyringType), http.StatusBadRequest)
			return
		}

		at := atReader.ReadTokenFromKeyring(perReq.KeyringType, perReq.TokenName)
		if at == nil || at.Id != perReq.AuthTokenId {
			writeError(w, "stored auth token's id doesn't match the one provided", http.StatusBadRequest)
			return
		}

		repo, err := cache.NewRepository(ctx, store)
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		foundP, err := repo.LookupPersona(ctx, perReq.BoundaryAddr, perReq.KeyringType, perReq.TokenName)
		if err != nil {
			writeError(w, "error performing persona lookup", http.StatusInternalServerError)
			return
		}

		if err = repo.AddPersona(ctx, perReq.toPersona()); err != nil {
			writeError(w, "Failed to add a persona", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

		if foundP == nil || foundP.AuthTokenId != at.Id {
			// If this was a new persona or an updated auth token refresh the cache.
			refresher.refresh()
		}
	}, nil
}
