// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

type refresher interface {
	refresh()
}

// keyringToken has keyring held auth token information.
type keyringToken struct {
	// The keyring type used by boundary to access the auth token
	KeyringType string
	// The token identifier for the provided keyring type that holds the auth token
	TokenName string
}

// userTokenToAdd is the request body to this handler.
type userTokenToAdd struct {
	// BoundaryAddr is a required field for all requests
	BoundaryAddr string
	// The id of the auth token asserted to be attempted to be added
	AuthTokenId string
	// Keyring is the keyring info used when adding an auth token held in
	// keyring to the daemon.
	Keyring *keyringToken
}

func newTokenHandlerFunc(ctx context.Context, repo *cache.Repository, refresher refresher) (http.HandlerFunc, error) {
	const op = "daemon.newPersonaHandlerFunc"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is nil")
	case util.IsNil(refresher):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refresher is nil")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != http.MethodPost {
			writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var perReq userTokenToAdd

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
		case perReq.BoundaryAddr == "":
			writeError(w, "BoundaryAddr is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.Keyring == nil:
			writeError(w, "TokenName is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.AuthTokenId == "":
			writeError(w, "AuthTokenId is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.Keyring != nil:
			switch {
			case perReq.Keyring.TokenName == "":
				writeError(w, "TokenName is a required field but was empty", http.StatusBadRequest)
				return
			case perReq.Keyring.KeyringType == "":
				writeError(w, "KeyringType is a required field but was empty", http.StatusBadRequest)
				return
			case perReq.Keyring.KeyringType == base.NoneKeyring:
				// TODO: Support personas that have tokens not stored in a keyring
				writeError(w, fmt.Sprintf("KeyringType is set to %s which is not supported", perReq.Keyring.KeyringType), http.StatusBadRequest)
				return
			}
		}

		tok, err := repo.LookupToken(ctx, perReq.AuthTokenId)
		if err != nil {
			writeError(w, "error performing auth token lookup", http.StatusInternalServerError)
			return
		}

		kt := cache.KeyringToken{
			KeyringType: perReq.Keyring.KeyringType,
			TokenName:   perReq.Keyring.TokenName,
			AuthTokenId: perReq.AuthTokenId,
		}
		if err = repo.AddKeyringToken(ctx, perReq.BoundaryAddr, kt); err != nil {
			writeError(w, "Failed to add a token", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

		// TODO: Figure out how to refresh only when the user id has changed
		// and not every time the auth token changes.
		if tok == nil || tok.Id != perReq.AuthTokenId {
			refresher.refresh()
		}
	}, nil
}
