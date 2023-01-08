package authmethods

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/ldap"
	ldapstore "github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/action"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"google.golang.org/grpc/codes"
)

var ldapMaskManager handlers.MaskManager

func init() {
	var err error
	if oidcMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&ldapstore.AuthMethod{}}, handlers.MaskSource{&pb.AuthMethod{}, &pb.LdapAuthMethodAttributes{}}); err != nil {
		panic(err)
	}

	IdActions[ldap.Subtype] = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.ChangeState,
		action.Authenticate,
	}
}

const (
	urlsField                 = "attributes.urls"
	bindDnField               = "attributes.bind_dn"
	bindPasswordField         = "attributes.bind_password"
	clientCertificateField    = "attributes.client_certificate"
	clientCertificateKeyField = "attributes.client_certificate_key"
	certificatesField         = "attributes.certificates"
	accountAttributesMapField = "attributes.account_attribute_maps"
)

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

	urls := make([]*url.URL, 0, len(attrs.GetUrls()))
	for _, urlStr := range attrs.GetUrls() {
		u, err := url.Parse(urlStr)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse %q into a url", urlStr))
		}
		urls = append(urls, u)
	}
	u, err := ldap.NewAuthMethod(ctx, scopeId, urls, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method: %v.", err)
	}
	return u, nil
}

// validateLdapAttributes implements a handlers.CustomValidatorFunc(...) to be
// used when validating requests with ldap attributes.
func validateLdapAttributes(ctx context.Context, attrs *pb.LdapAuthMethodAttributes, badFields map[string]string) {
	if attrs == nil {
		// LDAP attributes are required when creating an LDAP auth method.
		badFields[attributesField] = "Attributes are required for creating an LDAP auth method."
		return
	}
	if len(attrs.Urls) == 0 {
		badFields[urlsField] = "At least one URL is required"
	}
	if len(attrs.GetUrls()) > 0 {
		badUrlMsgs := []string{}
		for _, rawUrl := range attrs.GetUrls() {
			u, err := url.Parse(rawUrl)
			if err != nil {
				badUrlMsgs = append(badUrlMsgs, fmt.Sprintf("%q is not a valid url", rawUrl))
			}
			if u.Scheme != "ldap" && u.Scheme != "ldaps" {
				badUrlMsgs = append(badUrlMsgs, fmt.Sprintf("%s scheme in url %q is not either ldap or ldaps", u.Scheme, u.String()))
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
	if attrs.GetBindDn().GetValue() != "" && attrs.GetBindPassword().GetValue() == "" {
		badFields[bindPasswordField] = fmt.Sprintf("%s is missing required %s field", bindDnField, bindPasswordField)
	}
	if attrs.GetBindPassword().GetValue() != "" && attrs.GetBindDn().GetValue() == "" {
		badFields[bindDnField] = fmt.Sprintf("%s is missing required %s field", bindPasswordField, bindDnField)
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
}
