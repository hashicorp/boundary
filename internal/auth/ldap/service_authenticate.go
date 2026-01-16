// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/iam"
)

type (
	// AuthenticatorFactory is used by "service functions" to create a new
	// ldap.Authenticator (typically an ldap.Repository)
	AuthenticatorFactory func() (Authenticator, error)

	// LookupUserFactory is used by "service functions" to create a new
	// LookupUser (typically an iam repo)
	LookupUserFactory func() (LookupUser, error)

	// AuthTokenCreatorFactory is used by "service functions" to create a new
	// AuthTokenCreator (typically an auth token repo)
	AuthTokenCreatorFactory func() (AuthTokenCreator, error)
)

// Authenticate is an ldap domain service function for handling an LDAP
// authentication flow. On success, it returns an auth token.
//
// The service operation includes:
//   - Authenticate the user against the auth method's configured ldap server.
//   - Use iam.(Repository).LookupUserWithLogin(...) look up the iam.User matching the Account.
//   - Use the authtoken.(Repository).CreateAuthToken(...) to create a pending auth token for the authenticated user.
func Authenticate(
	ctx context.Context,
	authenticatorFn AuthenticatorFactory,
	lookupUserFn LookupUserFactory,
	tokenCreatorFn AuthTokenCreatorFactory,
	authMethodId, loginName, password string,
) (*authtoken.AuthToken, error) {
	const op = "ldap.Authenticate"
	switch {
	case authenticatorFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing authenticator factory")
	case lookupUserFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing lookup user factory")
	case tokenCreatorFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token creator factory")
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case loginName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing login name")
	case password == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password")
	}

	r, err := authenticatorFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	acct, err := r.Authenticate(ctx, authMethodId, loginName, password)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	l, err := lookupUserFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	user, err := l.LookupUserWithLogin(ctx, acct.PublicId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	at, err := tokenCreatorFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	token, err := at.CreateAuthToken(ctx, user, acct.PublicId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if err := event.WriteObservation(ctx, op, event.WithDetails("user_id", user.GetPublicId(), "auth_token_start",
		token.GetCreateTime(), "auth_token_end", token.GetExpirationTime())); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to write observation event for authenticate method"))
	}
	return token, nil
}

type Authenticator interface {
	Authenticate(ctx context.Context, authMethodId, loginName, password string) (*Account, error)
}

type LookupUser interface {
	LookupUserWithLogin(ctx context.Context, accountId string, opt ...iam.Option) (*iam.User, error)
}

type AuthTokenCreator interface {
	CreateAuthToken(ctx context.Context, withIamUser *iam.User, withAuthAccountId string, opt ...authtoken.Option) (*authtoken.AuthToken, error)
}
