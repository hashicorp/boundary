package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateAuthMethod creates m (*AuthMethod) in the repo and returns the newly
// created AuthMethod (with its PublicId set) along with its associated Value
// Objects of SigningAlgs, CallbackUrls, AudClaims (optional) and Certificates
// (optional).
//
// Supported options WithName, WithDescription. All other options are
// ignored.
func (r *Repository) CreateAuthMethod(ctx context.Context, m *AuthMethod, opt ...Option) (*AuthMethod, error) {
	panic("to-do")
}

// LookupAuthMethod will lookup an auth method in the repo, along with its
// associated Value Objects of SigningAlgs, CallbackUrls, AudClaims and
// Certificates. If it's not found, it will return nil, nil.  No options are
// currently supported.
func (r *Repository) LookupAuthMethod(ctx context.Context, publicId string, _ ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).LookupAuthMethod"
	if publicId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	authMethods, err := r.getAuthMethods(ctx, publicId, nil)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	if len(authMethods) > 1 {
		return nil, errors.New(errors.NotSpecificIntegrity, op, fmt.Sprintf("auth method id %s returned more than one result", publicId))
	}
	if authMethods == nil {
		return nil, nil
	}
	return authMethods[0], nil
}

// ListAuthMethods returns a slice of AuthMethods for the scopeId. WithLimit
// and WithOrder options are supported and all other options are ignored.
func (r *Repository) ListAuthMethods(ctx context.Context, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	const op = "oidc.(Repository).ListAuthMethods"
	if len(scopeIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing scope IDs")
	}
	authMethods, err := r.getAuthMethods(ctx, "", scopeIds, opt...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return authMethods, nil
}

// DeleteAuthMethod will delete the auth method from the repository.  No options
// are currently supported.
func (r *Repository) DeleteAuthMethod(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "oidc.(Repository).DeleteAuthMethod"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	am := AllocAuthMethod()
	am.PublicId = publicId

	if err := r.reader.LookupById(ctx, &am); err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}

	metadata := am.oplog(oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			rowsDeleted, err := w.Delete(ctx, &am, db.WithOplog(oplogWrapper, metadata))
			if err == nil && rowsDeleted > 1 {
				return errors.New(errors.MultipleRecords, op, "multiple records")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to delete %s", publicId)))
	}
	return rowsDeleted, nil
}

// UpdateAuthMethod will update the auth method in the repository and return the
// written auth method. fieldMaskPaths provides field_mask.proto paths for
// fields that should be updated.  Fields will be set to NULL if the field is a
// zero value and included in fieldMask. Name, Description, State, DiscoveryUrl,
// ClientId, ClientSecret, MaxAge are all updatable fields.  The AuthMethod's
// Value Objects of SigningAlgs, CallbackUrls, AudClaims and Certificates are
// also updatable. if no updatable fields are included in the fieldMaskPaths,
// then an error is returned.  No options are currently supported.
//
// Successful updates must invalidate (delete) the Repository's cache of the
// oidc.Provider for the AuthMethod.
func (r *Repository) UpdateAuthMethod(ctx context.Context, m *AuthMethod, version uint32, fieldMaskPaths []string, _ ...Option) (*AuthMethod, error) {
	panic("to-do")
}

// TestAuthMethod will test/validate the provided AuthMethod.
//
// It will verify that all required fields for a working AuthMethod have values.
//
// If the AuthMethod contains a DiscoveryUrl for an OIDC provider, TestAuthMethod
// retrieves the OpenID Configuration document. The values in the AuthMethod
// (and associated data) are validated with the retrieved document. The issuer and
// id token signing algorithm in the configuration are validated with the
// retrieved document. TestAuthMethod also verifies the authorization, token,
// and user_info endpoints by connecting to each and uses any certificates in the
// configuration as trust anchors to confirm connectivity.
//
// No options are currently supported.
func (r *Repository) TestAuthMethod(ctx context.Context, m *AuthMethod, opt ...Option) error {
	panic("to-do")
}

// MakeInactive will transision an OIDC auth method from either the
// ActivePrivateState or the ActivePublicState into the temporary StoppingState
// and then, after a small amount of time, to the InactiveState.
func (r *Repository) MakeInactive(ctx context.Context, authMethodId string, _ ...Option) error {
	panic("to-do")
}

// MakePrivate will transision an OIDC auth method from either the
// InactiveState or the ActivePublicState into the temporary StoppingState
// and then, after a small amount of time, to the ActivePrivateState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.TestAuthMethod(...) succeeds. No options are currently supported.
func (r *Repository) MakePrivate(ctx context.Context, authMethodId string, opt ...Option) error {
	panic("to-do")
}

// MakePublic will transision an OIDC auth method from either the
// InactiveState or the ActivePrivateState into the temporary StoppingState
// and then, after a small amount of time, to the ActivePublicState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.TestAuthMethod(...) succeeds. No options are currently supported.
func (r *Repository) MakePublic(ctx context.Context, authMethodId string, opt ...Option) error {
	panic("to-do")
}

// upsertAccount will create/update account using claims from the user's ID Token.
func (r *Repository) upsertAccount(ctx context.Context, authMethodId string, IdTokenClaims map[string]interface{}) (*Account, error) {
	panic("to-do")
}
