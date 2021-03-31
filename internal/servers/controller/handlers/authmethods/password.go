package authmethods

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	pwstore "github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pba "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"google.golang.org/grpc/codes"
)

const (
	// password field names
	loginNameField = "login_name"
	passwordField  = "password"
)

var pwMaskManager handlers.MaskManager

func init() {
	var err error
	if pwMaskManager, err = handlers.NewMaskManager(&pwstore.AuthMethod{}, &pb.AuthMethod{}, &pb.PasswordAuthMethodAttributes{}); err != nil {
		panic(err)
	}

	IdActions[auth.PasswordSubtype] = action.ActionSet{
		action.Read,
		action.Update,
		action.Delete,
		action.Authenticate,
	}
}

// createPwInRepo creates a password auth method in a repo and returns the result.
// This method should never return a nil AuthMethod without returning an error.
func (s Service) createPwInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*password.AuthMethod, error) {
	u, err := toStoragePwAuthMethod(scopeId, item)
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
	u, err := toStoragePwAuthMethod(scopeId, item)
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

func (s Service) authenticateWithPwRepo(ctx context.Context, scopeId, authMethodId, loginName, pw string) (*pba.AuthToken, error) {
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

	token, err := authtoken.EncryptToken(ctx, s.kms, scopeId, tok.GetPublicId(), tok.GetToken())
	if err != nil {
		return nil, err
	}

	tok.Token = tok.GetPublicId() + "_" + token
	prot := toAuthTokenProto(tok)

	scp, err := iamRepo.LookupScope(ctx, u.GetScopeId())
	if err != nil {
		return nil, err
	}
	if scp == nil {
		return nil, err
	}
	prot.Scope = &scopes.ScopeInfo{
		Id:            scp.GetPublicId(),
		Type:          scp.GetType(),
		ParentScopeId: scp.GetParentId(),
	}

	return prot, nil
}

func toStoragePwAuthMethod(scopeId string, item *pb.AuthMethod) (*password.AuthMethod, error) {
	const op = "authmethod_service.toStoragePwAuthMethod"
	if item == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil auth method.")
	}
	var opts []password.Option
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := password.NewAuthMethod(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for creation: %v.", err)
	}

	pwAttrs := &pb.PasswordAuthMethodAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
			map[string]string{attributesField: "Attribute fields do not match the expected format."})
	}
	if pwAttrs.GetMinLoginNameLength() != 0 {
		u.MinLoginNameLength = pwAttrs.GetMinLoginNameLength()
	}
	if pwAttrs.GetMinPasswordLength() != 0 {
		u.MinPasswordLength = pwAttrs.GetMinPasswordLength()
	}
	return u, nil
}
