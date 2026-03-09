// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/ldap"
	ldapstore "github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/types/action"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"google.golang.org/grpc/codes"
)

var ldapMaskManager handlers.MaskManager

func init() {
	var err error
	if ldapMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{
			&ldapstore.AuthMethod{},
		},
		handlers.MaskSource{&pb.AuthMethod{}, &pb.LdapAuthMethodAttributes{}},
	); err != nil {
		panic(err)
	}

	IdActions[ldap.Subtype] = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.Authenticate,
	)
}

const (
	urlsField                 = "attributes.urls"
	bindDnField               = "attributes.bind_dn"
	bindPasswordField         = "attributes.bind_password"
	clientCertificateField    = "attributes.client_certificate"
	clientCertificateKeyField = "attributes.client_certificate_key"
	certificatesField         = "attributes.certificates"
	accountAttributesMapField = "attributes.account_attribute_maps"
	derefAliasesField         = "attributes.dereference_aliases"
)

func (s Service) authenticateLdap(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateLdap"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil request.")
	}
	if authResults == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil auth results.")
	}
	reqAttrs := req.GetLdapLoginAttributes()

	ldapRepo, err := s.ldapRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	ldapFn := func() (ldap.Authenticator, error) {
		return ldapRepo, nil
	}

	iamRepo, err := s.iamRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	iamFn := func() (ldap.LookupUser, error) {
		return iamRepo, nil
	}

	atRepo, err := s.atRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	atFn := func() (ldap.AuthTokenCreator, error) {
		return atRepo, nil
	}

	rawTk, err := ldap.Authenticate(ctx, ldapFn, iamFn, atFn, req.GetAuthMethodId(), reqAttrs.GetLoginName(), reqAttrs.GetPassword())
	if err != nil {
		// let's not send back too much info about the error
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Unauthenticated, "Unable to authenticate.")
	}
	tk, err := s.ConvertInternalAuthTokenToApiAuthToken(
		ctx,
		rawTk,
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return s.convertToAuthenticateResponse(ctx, req, authResults, tk)
}

// createLdapInRepo creates an ldap auth method in a repo and returns the result.
// This method should never return a nil AuthMethod without returning an error.
func (s Service) createLdapInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*ldap.AuthMethod, error) {
	u, err := toStorageLdapAuthMethod(ctx, scopeId, item)
	if err != nil {
		return nil, err
	}
	repo, err := s.ldapRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateAuthMethod(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create auth method: %w", err)
	}
	return out, nil
}

func (s Service) updateLdapInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.AuthMethod) (*ldap.AuthMethod, error) {
	u, err := toStorageLdapAuthMethod(ctx, scopeId, item)
	if err != nil {
		return nil, err
	}

	version := item.GetVersion()
	u.PublicId = id

	dbMask := ldapMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	repo, err := s.ldapRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAuthMethod(ctx, u, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update auth method: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist or incorrect version provided or no changes were made to the existing AuthMethod.", id)
	}
	return out, nil
}

func toStorageLdapAuthMethod(ctx context.Context, scopeId string, in *pb.AuthMethod) (out *ldap.AuthMethod, err error) {
	const op = "authmethod_service.toStorageLdapAuthMethod"
	if in == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil auth method.")
	}
	attrs := in.GetLdapAuthMethodsAttributes()

	var opts []ldap.Option
	if in.GetName() != nil {
		opts = append(opts, ldap.WithName(ctx, in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, ldap.WithDescription(ctx, in.GetDescription().GetValue()))
	}
	var urls []*url.URL
	if attrs != nil {
		if attrs.GetState() != "" {
			opts = append(opts, ldap.WithOperationalState(ctx, ldap.AuthMethodState(attrs.GetState())))
		}
		if attrs.StartTls {
			opts = append(opts, ldap.WithStartTLS(ctx))
		}
		if attrs.InsecureTls {
			opts = append(opts, ldap.WithInsecureTLS(ctx))
		}
		if attrs.DiscoverDn {
			opts = append(opts, ldap.WithDiscoverDn(ctx))
		}
		if attrs.AnonGroupSearch {
			opts = append(opts, ldap.WithAnonGroupSearch(ctx))
		}
		if attrs.UpnDomain.GetValue() != "" {
			opts = append(opts, ldap.WithUpnDomain(ctx, attrs.UpnDomain.GetValue()))
		}
		if attrs.UserDn.GetValue() != "" {
			opts = append(opts, ldap.WithUserDn(ctx, attrs.UserDn.GetValue()))
		}
		if attrs.UserAttr.GetValue() != "" {
			opts = append(opts, ldap.WithUserAttr(ctx, attrs.UserAttr.GetValue()))
		}
		if attrs.UserFilter.GetValue() != "" {
			opts = append(opts, ldap.WithUserFilter(ctx, attrs.UserFilter.GetValue()))
		}
		if attrs.EnableGroups {
			opts = append(opts, ldap.WithEnableGroups(ctx))
		}
		if attrs.GroupDn.GetValue() != "" {
			opts = append(opts, ldap.WithGroupDn(ctx, attrs.GroupDn.GetValue()))
		}
		if attrs.GroupAttr.GetValue() != "" {
			opts = append(opts, ldap.WithGroupAttr(ctx, attrs.GroupAttr.GetValue()))
		}
		if attrs.GroupFilter.GetValue() != "" {
			opts = append(opts, ldap.WithGroupFilter(ctx, attrs.GroupFilter.GetValue()))
		}
		if len(attrs.Certificates) > 0 {
			certs, err := ldap.ParseCertificates(ctx, attrs.Certificates...)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			opts = append(opts, ldap.WithCertificates(ctx, certs...))
		}
		if attrs.ClientCertificate != nil || attrs.ClientCertificateKey != nil {
			keyBlk, _ := pem.Decode([]byte(attrs.ClientCertificateKey.GetValue()))
			if keyBlk == nil {
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to parse %s PEM", clientCertificateKeyField))
			}
			certBlk, _ := pem.Decode([]byte(attrs.ClientCertificate.GetValue()))
			if certBlk == nil {
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to parse %s PEM", clientCertificateField))
			}
			cc, err := x509.ParseCertificate(certBlk.Bytes)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse %s ASN.1 DER", clientCertificateField))
			}
			opts = append(opts, ldap.WithClientCertificate(ctx, keyBlk.Bytes, cc))
		}
		if attrs.BindDn.GetValue() != "" || attrs.BindPassword.GetValue() != "" {
			opts = append(opts, ldap.WithBindCredential(ctx, attrs.BindDn.GetValue(), attrs.BindPassword.GetValue()))
		}
		if attrs.UseTokenGroups {
			opts = append(opts, ldap.WithUseTokenGroups(ctx))
		}
		if len(attrs.AccountAttributeMaps) > 0 {
			attribMaps, err := ldap.ParseAccountAttributeMaps(ctx, attrs.AccountAttributeMaps...)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse %s", accountAttributesMapField))
			}
			fromToMap := map[string]ldap.AccountToAttribute{}
			for _, m := range attribMaps {
				fromToMap[m.From] = ldap.AccountToAttribute(m.To)
			}
			opts = append(opts, ldap.WithAccountAttributeMap(ctx, fromToMap))
		}

		if len(attrs.GetUrls()) > 0 {
			urls = make([]*url.URL, 0, len(attrs.GetUrls()))
			for _, urlStr := range attrs.GetUrls() {
				u, err := url.Parse(urlStr)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse %q into a url", urlStr))
				}
				urls = append(urls, u)
			}
			opts = append(opts, ldap.WithUrls(ctx, urls...))
		}
		if attrs.GetMaximumPageSize() > 0 {
			opts = append(opts, ldap.WithMaximumPageSize(ctx, attrs.MaximumPageSize))
		}
		if attrs.GetDereferenceAliases().GetValue() != "" {
			opts = append(opts, ldap.WithDerefAliases(ctx, ldap.DerefAliasType(attrs.GetDereferenceAliases().GetValue())))
		}
	}
	u, err := ldap.NewAuthMethod(ctx, scopeId, opts...)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.InvalidParameter), err):
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, err.Error())
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method: %v.", err)
		}
	}
	return u, nil
}

// validateLdapAttributes implements a handlers.CustomValidatorFunc(...) to be
// used when validating requests with ldap attributes.
func validateLdapAttributes(ctx context.Context, attrs *pb.LdapAuthMethodAttributes, badFields map[string]string) {
	if attrs == nil {
		// LDAP attributes are required when creating an LDAP auth method.
		// badFields[attributesField] = "Attributes are required for creating an LDAP auth method."
		return
	}
	if len(attrs.GetUrls()) > 0 {
		badUrlMsgs := []string{}
		for _, rawUrl := range attrs.GetUrls() {
			u, err := url.Parse(rawUrl)
			if err != nil {
				badUrlMsgs = append(badUrlMsgs, fmt.Sprintf("%q is not a valid url", rawUrl))
				continue
			}
			if u.Scheme != "ldap" && u.Scheme != "ldaps" {
				badUrlMsgs = append(badUrlMsgs, fmt.Sprintf("%s scheme in url %q is not either ldap or ldaps", u.Scheme, u.String()))
			}
			if u.Port() != "" {
				port, err := strconv.Atoi(u.Port())
				if err != nil || port > math.MaxUint16 {
					badUrlMsgs = append(badUrlMsgs, fmt.Sprintf("port %s in url %s is not valid", u.Port(), u.String()))
				}
			}
		}
		if len(badUrlMsgs) > 0 {
			badFields[urlsField] = strings.Join(badUrlMsgs, " / ")
		}
	}
	if len(attrs.GetCertificates()) > 0 {
		if _, err := ldap.ParseCertificates(ctx, attrs.GetCertificates()...); err != nil {
			badFields[certificatesField] = fmt.Sprintf("invalid %s: %s", certificatesField, err.Error())
		}
	}
	if attrs.GetClientCertificate().GetValue() != "" && attrs.GetClientCertificateKey().GetValue() == "" {
		badFields[clientCertificateKeyField] = fmt.Sprintf("%s is missing required %s field", clientCertificateField, clientCertificateKeyField)
	}
	if attrs.GetClientCertificateKey().GetValue() != "" && attrs.GetClientCertificate().GetValue() == "" {
		badFields[clientCertificateField] = fmt.Sprintf("%s is missing required %s field", clientCertificateKeyField, clientCertificateField)
	}
	if attrs.GetClientCertificate().GetValue() != "" {
		if _, err := ldap.ParseCertificates(ctx, attrs.GetClientCertificate().GetValue()); err != nil {
			badFields[clientCertificateField] = fmt.Sprintf("invalid %s: %s", clientCertificateField, err.Error())
		}
	}
	if attrs.GetClientCertificateKey().GetValue() != "" {
		blk, _ := pem.Decode([]byte(attrs.GetClientCertificateKey().GetValue()))
		if blk == nil || blk.Bytes == nil {
			badFields[clientCertificateKeyField] = fmt.Sprintf("%s is not encoded as a valid pem", clientCertificateKeyField)
		} else {
			if _, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
				badFields[clientCertificateKeyField] = fmt.Sprintf("%s is not a valid private key", clientCertificateKeyField)
			}
		}
	}
	if len(attrs.AccountAttributeMaps) > 0 {
		if _, err := ldap.ParseAccountAttributeMaps(ctx, attrs.AccountAttributeMaps...); err != nil {
			badFields[accountAttributesMapField] = fmt.Sprintf("invalid %s (unable to parse)", accountAttributesMapField)
		}
	}
	if attrs.GetDereferenceAliases().GetValue() != "" {
		d := ldap.DerefAliasType(attrs.GetDereferenceAliases().GetValue())
		if err := d.IsValid(ctx); err != nil {
			badFields[derefAliasesField] = fmt.Sprintf("%s is not a valid %s", attrs.GetDereferenceAliases().GetValue(), derefAliasesField)
		}
	}
}

func validateAuthenticateLdapRequest(ctx context.Context, req *pbs.AuthenticateRequest) error {
	const op = "authmethods.(Service).validateAuthenticateLdapRequest"
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

	attrs := req.GetLdapLoginAttributes()
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
			tokenType = req.GetTokenType() //nolint:all
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
