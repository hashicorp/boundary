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

type readTokenFromKeyringer interface {
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

func newPersonaHandlerFunc(ctx context.Context, store *cache.Store, atReader readTokenFromKeyringer, refresher refresher) (http.HandlerFunc, error) {
	const op = "daemon.newPersonaHandlerFunc"
	switch {
	case util.IsNil(store):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "store is missing")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var perReq personaToAdd

		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "unable to read request body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(data, &perReq); err != nil {
			http.Error(w, "unable to parse request body", http.StatusBadRequest)
			return
		}

		switch {
		case perReq.TokenName == "":
			http.Error(w, "Token name is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.KeyringType == "":
			http.Error(w, "Keyring Type is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.BoundaryAddr == "":
			http.Error(w, "Boundary Address is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.AuthTokenId == "":
			http.Error(w, "AuthTokenId is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.KeyringType == base.NoneKeyring:
			// TODO: Support personas that have tokens not stored in a keyring
			http.Error(w, fmt.Sprintf("keyring type is set to %s but a keyring which is not supported", perReq.KeyringType), http.StatusBadRequest)
			return
		}

		at := atReader.ReadTokenFromKeyring(perReq.KeyringType, perReq.TokenName)
		if at == nil || at.Id != perReq.AuthTokenId {
			http.Error(w, "stored auth token's id doesn't match the one provided", http.StatusBadRequest)
			return
		}

		repo, err := cache.NewRepository(ctx, store)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		foundP, err := repo.LookupPersona(ctx, perReq.BoundaryAddr, perReq.KeyringType, perReq.TokenName)
		if err != nil {
			http.Error(w, "error performign persona lookup", http.StatusInternalServerError)
			return
		}

		if err = repo.AddPersona(ctx, perReq.toPersona()); err != nil {
			http.Error(w, "Failed to add a persona", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

		if foundP == nil || foundP.AuthTokenId != at.Id {
			// If this was a new persona or an updated auth token refresh the cache.
			refresher.refresh()
		}
	}, nil
}
