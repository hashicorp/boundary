// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

type refresher interface {
	refresh()
}

// KeyringToken has keyring held auth token information.
type KeyringToken struct {
	// The keyring type used by boundary to access the auth token
	KeyringType string `json:"keyring_type"`
	// The token identifier for the provided keyring type that holds the auth token
	TokenName string `json:"token_name"`
}

// userTokenToAdd is the request body to this handler.
type UpsertTokenRequest struct {
	// BoundaryAddr is a required field for all requests
	BoundaryAddr string `json:"boundary_addr"`
	// The id of the auth token asserted to be attempted to be added
	AuthTokenId string `json:"auth_token_id"`
	// The raw auth token for this user. Either this field or the Keyring field
	// must be set but not both.
	AuthToken string `json:"auth_token"`
	// Keyring is the keyring info used when adding an auth token held in
	// keyring to the daemon.
	Keyring *KeyringToken `json:"keyring"`
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
		var perReq UpsertTokenRequest

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
			writeError(w, "boundary_addr is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.AuthTokenId == "":
			writeError(w, "auth_token_id is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.Keyring == nil && perReq.AuthToken == "":
			writeError(w, "Either keyring info or the auth_token must be provided but were empty", http.StatusBadRequest)
			return
		case perReq.Keyring != nil:
			switch {
			case perReq.Keyring.TokenName == "":
				writeError(w, "keyring.token_name is a required field but was empty", http.StatusBadRequest)
				return
			case perReq.Keyring.KeyringType == "":
				writeError(w, "keyring.keyring_type is a required field but was empty", http.StatusBadRequest)
				return
			case perReq.Keyring.KeyringType == base.NoneKeyring:
				writeError(w, fmt.Sprintf("keyring.keyring_type is set to %s which is not supported", perReq.Keyring.KeyringType), http.StatusBadRequest)
				return
			}
		case perReq.AuthToken != "":
			switch {
			case !strings.HasPrefix(perReq.AuthToken, perReq.AuthTokenId):
				writeError(w, "auth_token_id doesn't match the auth_token's prefix", http.StatusBadRequest)
				return
			}
		}

		tok, err := repo.LookupToken(ctx, perReq.AuthTokenId)
		if err != nil {
			writeError(w, "error performing auth token lookup", http.StatusInternalServerError)
			return
		}

		switch {
		case perReq.Keyring != nil:
			kt := cache.KeyringToken{
				KeyringType: perReq.Keyring.KeyringType,
				TokenName:   perReq.Keyring.TokenName,
				AuthTokenId: perReq.AuthTokenId,
			}
			if err = repo.AddKeyringToken(ctx, perReq.BoundaryAddr, kt); err != nil {
				writeError(w, "Failed to add a keyring stored token", http.StatusInternalServerError)
				return
			}
		case perReq.AuthToken != "":
			if err = repo.AddRawToken(ctx, perReq.BoundaryAddr, perReq.AuthToken); err != nil {
				writeError(w, "Failed to add a raw token", http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)

		if tok == nil {
			refresher.refresh()
		}
	}, nil
}
