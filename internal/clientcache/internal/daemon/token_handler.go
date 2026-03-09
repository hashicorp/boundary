// Copyright IBM Corp. 2020, 2025
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
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-hclog"
)

const redactedString = "/*redacted*/"

type refresher interface {
	refresh()
}

// KeyringToken has keyring held auth token information.
type KeyringToken struct {
	// The keyring type used by boundary to access the auth token
	KeyringType string `json:"keyring_type,omitempty"`
	// The token identifier for the provided keyring type that holds the auth token
	TokenName string `json:"token_name,omitempty"`
}

// userTokenToAdd is the request body to this handler.
type UpsertTokenRequest struct {
	// BoundaryAddr is a required field for all requests
	BoundaryAddr string `json:"boundary_addr,omitempty"`
	// The id of the auth token asserted to be attempted to be added
	AuthTokenId string `json:"auth_token_id,omitempty"`
	// The raw auth token for this user. Either this field or the Keyring field
	// must be set but not both.
	AuthToken string `json:"auth_token,omitempty"`
	// Keyring is the keyring info used when adding an auth token held in
	// keyring to the daemon.
	Keyring *KeyringToken `json:"keyring,omitempty"`
}

func (u *UpsertTokenRequest) String() string {
	if u == nil {
		return "nil"
	}
	out := fmt.Sprintf("BoundaryAddr: %q, AuthTokenId: %q", u.BoundaryAddr, u.AuthTokenId)
	if u.Keyring != nil {
		out = fmt.Sprintf("%s, Keyring: %+v", out, *u.Keyring)
	}
	if len(u.AuthToken) > 0 {
		// Don't print out the auth token string, but do indicate if it has the
		// same prefix as the provided auth token id.
		redactedAuthTokenStr := redactedString
		if strings.HasPrefix(u.AuthToken, u.AuthTokenId) {
			redactedAuthTokenStr = fmt.Sprintf("%s_%s", u.AuthTokenId, redactedAuthTokenStr)
		}
		out = fmt.Sprintf("%s, AuthToken: %q", out, redactedAuthTokenStr)
	}
	return out
}

func newTokenHandlerFunc(ctx context.Context, repo *cache.Repository, refresher refresher, logger hclog.Logger) (http.HandlerFunc, error) {
	const op = "daemon.newTokenHandlerFunc"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is nil")
	case util.IsNil(logger):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "logger is nil")
	case util.IsNil(refresher):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refresher is nil")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		reqCtx := r.Context()

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
		logger.Debug("received add-token request", "request", perReq.String())

		switch {
		case perReq.BoundaryAddr == "":
			event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, "boundary_addr is a required field but was empty"), event.WithInfo("request", perReq.String()))
			writeError(w, "boundary_addr is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.AuthTokenId == "":
			event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, "auth_token_id is a required field but was empty"), event.WithInfo("request", perReq.String()))
			writeError(w, "auth_token_id is a required field but was empty", http.StatusBadRequest)
			return
		case perReq.Keyring == nil && perReq.AuthToken == "":
			event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, "either keyring info or the auth_token must be provided but were empty"), event.WithInfo("request", perReq.String()))
			writeError(w, "Either keyring info or the auth_token must be provided but were empty", http.StatusBadRequest)
			return
		case perReq.Keyring != nil:
			switch {
			case perReq.Keyring.TokenName == "":
				event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, "keyring.token_name is a required field but was empty"), event.WithInfo("request", perReq.String()))
				writeError(w, "keyring.token_name is a required field but was empty", http.StatusBadRequest)
				return
			case perReq.Keyring.KeyringType == "":
				event.WriteError(reqCtx, op, errors.New(reqCtx, errors.InvalidParameter, op, "keyring.keyring_type is a required field but was empty"), event.WithInfo("request", perReq.String()))
				writeError(w, "keyring.keyring_type is a required field but was empty", http.StatusBadRequest)
				return
			case perReq.Keyring.KeyringType == base.NoneKeyring:
				event.WriteError(reqCtx, op, errors.New(reqCtx, errors.InvalidParameter, op, "keyring.keyring_type is set to none which is not supported"), event.WithInfo("request", perReq.String()))
				writeError(w, fmt.Sprintf("keyring.keyring_type is set to %s which is not supported", perReq.Keyring.KeyringType), http.StatusBadRequest)
				return
			}
		case perReq.AuthToken != "":
			switch {
			case !strings.HasPrefix(perReq.AuthToken, perReq.AuthTokenId):
				event.WriteError(reqCtx, op, errors.New(reqCtx, errors.InvalidParameter, op, "auth_token_id doesn't match the auth_token's prefix"), event.WithInfo("request", perReq.String()))
				writeError(w, "auth_token_id doesn't match the auth_token's prefix", http.StatusBadRequest)
				return
			}
		}

		oldTok, err := repo.LookupToken(reqCtx, perReq.AuthTokenId)
		if err != nil {
			event.WriteError(reqCtx, op, err, event.WithInfoMsg("error when trying to look up existing cached auth token", "request", perReq.String()))
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
			if err = repo.AddKeyringToken(reqCtx, perReq.BoundaryAddr, kt); err != nil {
				errCode := http.StatusInternalServerError
				if errors.Match(errors.T(errors.Forbidden), err) {
					errCode = http.StatusForbidden
				}

				err := fmt.Errorf("Failed to add a keyring stored token with id %q: %w", perReq.AuthTokenId, err)
				event.WriteError(reqCtx, op, err, event.WithInfo("request", perReq.String()))
				writeError(w, err.Error(), errCode)
				return
			}
		case perReq.AuthToken != "":
			if err = repo.AddRawToken(reqCtx, perReq.BoundaryAddr, perReq.AuthToken); err != nil {
				errCode := http.StatusInternalServerError
				if errors.Match(errors.T(errors.Forbidden), err) {
					errCode = http.StatusForbidden
				}

				err := fmt.Errorf("Failed to add a raw token with id %q: %w", perReq.AuthTokenId, err)
				event.WriteError(reqCtx, op, err, event.WithInfo("request", perReq.String()))
				writeError(w, err.Error(), errCode)
				return
			}
		}

		newTok, err := repo.LookupToken(reqCtx, perReq.AuthTokenId)
		if err != nil {
			event.WriteError(reqCtx, op, err, event.WithInfoMsg("error when trying to look up newly added cached auth token", "request", perReq.String()))
			writeError(w, "error performing follow up auth token lookup", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

		if oldTok == nil && newTok != nil {
			logger.Debug("New auth token added to the cache. Initiating a cache refresh.", "request", perReq.String())
			refresher.refresh()
		}
	}, nil
}
