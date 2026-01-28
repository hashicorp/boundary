// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/password"
	pwstore "github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/types/action"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	pba "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"google.golang.org/grpc/codes"
)

const (
	// password field names
	loginNameField = "login_name"
	passwordField  = "password"
	loginCommand   = "login"
)

var pwMaskManager handlers.MaskManager

func init() {
	var err error
	if pwMaskManager, err = handlers.NewMaskManager(context.Background(), handlers.MaskDestination{&pwstore.AuthMethod{}}, handlers.MaskSource{&pb.AuthMethod{}, &pb.PasswordAuthMethodAttributes{}}); err != nil {
		panic(err)
	}

	IdActions[password.Subtype] = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.Authenticate,
	)
}

// createPwInRepo creates a password auth method in a repo and returns the result.
// This method should never return a nil AuthMethod without returning an error.
func (s Service) createPwInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*password.AuthMethod, error) {
	u, err := toStoragePwAuthMethod(ctx, scopeId, item)
	if err != nil {
		return nil, err
	}
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateAuthMethod(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create auth method: %w", err)
	}
	return out, err
}

func (s Service) updatePwInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.AuthMethod) (*password.AuthMethod, error) {
	u, err := toStoragePwAuthMethod(ctx, scopeId, item)
	if err != nil {
		return nil, err
	}

	version := item.GetVersion()
	u.PublicId = id

	dbMask := pwMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAuthMethod(ctx, u, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update auth method: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) authenticatePassword(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	reqAttrs := req.GetPasswordLoginAttributes()
	tok, err := s.authenticateWithPwRepo(ctx, authResults.Scope.GetId(), req.GetAuthMethodId(), reqAttrs.LoginName, reqAttrs.Password)
	if err != nil {
		return nil, err
	}
	return s.convertToAuthenticateResponse(ctx, req, authResults, tok)
}

func (s Service) authenticateWithPwRepo(ctx context.Context, scopeId, authMethodId, loginName, pw string) (*pba.AuthToken, error) {
	const op = "authmethods.(Service).authenticateWithPwRepo"
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		return nil, err
	}
	atRepo, err := s.atRepoFn()
	if err != nil {
		return nil, err
	}
	pwRepo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}

	acct, err := pwRepo.Authenticate(ctx, scopeId, authMethodId, loginName, pw)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Unauthenticated, "Unable to authenticate.")
	}

	u, err := iamRepo.LookupUserWithLogin(ctx, acct.GetPublicId())
	if err != nil {
		return nil, err
	}
	tok, err := atRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	if err != nil {
		return nil, err
	}

	if err := event.WriteObservation(ctx, op, event.WithDetails("user_id", u.GetPublicId(), "auth_token_start",
		tok.GetCreateTime(), "auth_token_end", tok.GetExpirationTime())); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to write observation event for authenticate method"))
	}

	return s.ConvertInternalAuthTokenToApiAuthToken(
		ctx,
		tok,
	)
}

func validateAuthenticatePasswordRequest(ctx context.Context, req *pbs.AuthenticateRequest) error {
	const op = "authmethods.(Service).validateAuthenticatePasswordRequest"
	badFields := make(map[string]string)

	requestInfo, ok := auth.GetRequestInfo(ctx)
	if !ok {
		return errors.New(ctx, errors.Internal, op, "no request info found")
	}

	for _, action := range requestInfo.Actions {
		switch action {
		case auth.CallbackAction:
			badFields["request_path"] = "callback is not a valid action for this auth method."
		}
	}

	attrs := req.GetPasswordLoginAttributes()
	switch {
	case attrs == nil:
		badFields["attributes"] = "This is a required field."
	default:
		if attrs.LoginName == "" {
			badFields["attributes.login_name"] = "This is a required field."
		}
		if attrs.Password == "" {
			badFields["attributes.password"] = "This is a required field."
		}
		if req.GetCommand() == "" {
			// TODO: Eventually, require a command. For now, fall back to "login" for backwards compat.
			req.Command = loginCommand
		}
		if req.Command != loginCommand {
			badFields[commandField] = "Invalid command for this auth method type."
		}
		tokenType := req.GetType()
		if tokenType == "" {
			// Fall back to deprecated field if type is not set
			tokenType = req.GetTokenType()
		}
		tType := strings.ToLower(strings.TrimSpace(tokenType))
		if tType != "" && tType != "token" && tType != "cookie" {
			badFields[tokenTypeField] = `The only accepted types are "token" and "cookie".`
		}
	}

	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}
	return nil
}

func toStoragePwAuthMethod(ctx context.Context, scopeId string, item *pb.AuthMethod) (*password.AuthMethod, error) {
	const op = "authmethod_service.toStoragePwAuthMethod"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil auth method.")
	}
	var opts []password.Option
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := password.NewAuthMethod(ctx, scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for creation: %v.", err)
	}

	pwAttrs := item.GetPasswordAuthMethodAttributes()
	if pwAttrs.GetMinLoginNameLength() != 0 {
		u.MinLoginNameLength = pwAttrs.GetMinLoginNameLength()
	}
	if pwAttrs.GetMinPasswordLength() != 0 {
		u.MinPasswordLength = pwAttrs.GetMinPasswordLength()
	}
	return u, nil
}
