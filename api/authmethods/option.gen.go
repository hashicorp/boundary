// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package authmethods

import (
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/api"
)

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made options are processed in ther order they
// appear in the function call, so for a given argument X, a succession of WithX
// or DefaultX calls will result in the last call taking effect.
type Option func(*options)

type options struct {
	postMap                 map[string]interface{}
	queryMap                map[string]string
	withAutomaticVersioning bool
	withSkipCurlOutput      bool
	withFilter              string
	withRefreshToken        string
	withPageSize            uint
	withRecursive           bool
}

func getDefaultOptions() options {
	return options{
		postMap:  make(map[string]interface{}),
		queryMap: make(map[string]string),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	var apiOpts []api.Option
	if opts.withSkipCurlOutput {
		apiOpts = append(apiOpts, api.WithSkipCurlOutput(true))
	}
	if opts.withFilter != "" {
		opts.queryMap["filter"] = opts.withFilter
	}
	if opts.withRefreshToken != "" {
		opts.queryMap["refresh_token"] = opts.withRefreshToken
	}
	if opts.withPageSize != 0 {
		opts.queryMap["page_size"] = strconv.FormatUint(uint64(opts.withPageSize), 10)
	}
	if opts.withRecursive {
		opts.queryMap["recursive"] = strconv.FormatBool(opts.withRecursive)
	}
	return opts, apiOpts
}

// If set, and if the version is zero during an update, the API will perform a
// fetch to get the current version of the resource and populate it during the
// update call. This is convenient but opens up the possibility for subtle
// order-of-modification issues, so use carefully.
func WithAutomaticVersioning(enable bool) Option {
	return func(o *options) {
		o.withAutomaticVersioning = enable
	}
}

// WithSkipCurlOutput tells the API to not use the current call for cURL output.
// Useful for when we need to look up versions.
func WithSkipCurlOutput(skip bool) Option {
	return func(o *options) {
		o.withSkipCurlOutput = true
	}
}

// WithRefreshToken tells the API to use the provided refresh token
// for listing operations on this resource.
func WithRefreshToken(refreshToken string) Option {
	return func(o *options) {
		o.withRefreshToken = refreshToken
	}
}

// WithPageSize tells the API use the provided page size for listing
// opertaions on this resource.
func WithPageSize(pageSize uint) Option {
	return func(o *options) {
		o.withPageSize = pageSize
	}
}

// WithFilter tells the API to filter the items returned using the provided
// filter term.  The filter should be in a format supported by
// hashicorp/go-bexpr.
func WithFilter(filter string) Option {
	return func(o *options) {
		o.withFilter = strings.TrimSpace(filter)
	}
}

// WithRecursive tells the API to use recursion for listing operations on this
// resource
func WithRecursive(recurse bool) Option {
	return func(o *options) {
		o.withRecursive = true
	}
}

func WithLdapAuthMethodAccountAttributeMaps(inAccountAttributeMaps []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["account_attribute_maps"] = inAccountAttributeMaps
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodAccountAttributeMaps() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["account_attribute_maps"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodAccountClaimMaps(inAccountClaimMaps []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["account_claim_maps"] = inAccountClaimMaps
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodAccountClaimMaps() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["account_claim_maps"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodAllowedAudiences(inAllowedAudiences []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["allowed_audiences"] = inAllowedAudiences
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodAllowedAudiences() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["allowed_audiences"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodAnonGroupSearch(inAnonGroupSearch bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["anon_group_search"] = inAnonGroupSearch
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodAnonGroupSearch() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["anon_group_search"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodApiUrlPrefix(inApiUrlPrefix string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["api_url_prefix"] = inApiUrlPrefix
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodApiUrlPrefix() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["api_url_prefix"] = nil
		o.postMap["attributes"] = val
	}
}

func WithAttributes(inAttributes map[string]interface{}) Option {
	return func(o *options) {
		o.postMap["attributes"] = inAttributes
	}
}

func DefaultAttributes() Option {
	return func(o *options) {
		o.postMap["attributes"] = nil
	}
}

func WithLdapAuthMethodBindDn(inBindDn string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["bind_dn"] = inBindDn
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodBindDn() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["bind_dn"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodBindPassword(inBindPassword string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["bind_password"] = inBindPassword
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodBindPassword() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["bind_password"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodCertificates(inCertificates []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["certificates"] = inCertificates
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodCertificates() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["certificates"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodClaimsScopes(inClaimsScopes []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["claims_scopes"] = inClaimsScopes
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodClaimsScopes() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["claims_scopes"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodClientCertificate(inClientCertificate string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_certificate"] = inClientCertificate
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodClientCertificate() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_certificate"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodClientCertificateKey(inClientCertificateKey string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_certificate_key"] = inClientCertificateKey
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodClientCertificateKey() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_certificate_key"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodClientId(inClientId string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_id"] = inClientId
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodClientId() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_id"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodClientSecret(inClientSecret string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_secret"] = inClientSecret
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodClientSecret() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["client_secret"] = nil
		o.postMap["attributes"] = val
	}
}

func WithDescription(inDescription string) Option {
	return func(o *options) {
		o.postMap["description"] = inDescription
	}
}

func DefaultDescription() Option {
	return func(o *options) {
		o.postMap["description"] = nil
	}
}

func WithOidcAuthMethodDisableDiscoveredConfigValidation(inDisableDiscoveredConfigValidation bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["disable_discovered_config_validation"] = inDisableDiscoveredConfigValidation
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodDisableDiscoveredConfigValidation() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["disable_discovered_config_validation"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodDiscoverDn(inDiscoverDn bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["discover_dn"] = inDiscoverDn
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodDiscoverDn() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["discover_dn"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodDryRun(inDryRun bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["dry_run"] = inDryRun
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodDryRun() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["dry_run"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodEnableGroups(inEnableGroups bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["enable_groups"] = inEnableGroups
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodEnableGroups() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["enable_groups"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodGroupAttr(inGroupAttr string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["group_attr"] = inGroupAttr
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodGroupAttr() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["group_attr"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodGroupDn(inGroupDn string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["group_dn"] = inGroupDn
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodGroupDn() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["group_dn"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodGroupFilter(inGroupFilter string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["group_filter"] = inGroupFilter
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodGroupFilter() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["group_filter"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodIdpCaCerts(inIdpCaCerts []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["idp_ca_certs"] = inIdpCaCerts
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodIdpCaCerts() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["idp_ca_certs"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodInsecureTls(inInsecureTls bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["insecure_tls"] = inInsecureTls
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodInsecureTls() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["insecure_tls"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodIssuer(inIssuer string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["issuer"] = inIssuer
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodIssuer() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["issuer"] = nil
		o.postMap["attributes"] = val
	}
}

func WithOidcAuthMethodMaxAge(inMaxAge uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["max_age"] = inMaxAge
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodMaxAge() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["max_age"] = nil
		o.postMap["attributes"] = val
	}
}

func WithPasswordAuthMethodMinLoginNameLength(inMinLoginNameLength uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_login_name_length"] = inMinLoginNameLength
		o.postMap["attributes"] = val
	}
}

func DefaultPasswordAuthMethodMinLoginNameLength() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_login_name_length"] = nil
		o.postMap["attributes"] = val
	}
}

func WithPasswordAuthMethodMinPasswordLength(inMinPasswordLength uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_password_length"] = inMinPasswordLength
		o.postMap["attributes"] = val
	}
}

func DefaultPasswordAuthMethodMinPasswordLength() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_password_length"] = nil
		o.postMap["attributes"] = val
	}
}

func WithName(inName string) Option {
	return func(o *options) {
		o.postMap["name"] = inName
	}
}

func DefaultName() Option {
	return func(o *options) {
		o.postMap["name"] = nil
	}
}

func WithOidcAuthMethodSigningAlgorithms(inSigningAlgorithms []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["signing_algorithms"] = inSigningAlgorithms
		o.postMap["attributes"] = val
	}
}

func DefaultOidcAuthMethodSigningAlgorithms() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["signing_algorithms"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodStartTls(inStartTls bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["start_tls"] = inStartTls
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodStartTls() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["start_tls"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodState(inState string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["state"] = inState
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodState() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["state"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodUpnDomain(inUpnDomain string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["upn_domain"] = inUpnDomain
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodUpnDomain() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["upn_domain"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodUrls(inUrls []string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["urls"] = inUrls
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodUrls() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["urls"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodUseTokenGroups(inUseTokenGroups bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["use_token_groups"] = inUseTokenGroups
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodUseTokenGroups() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["use_token_groups"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodUserAttr(inUserAttr string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["user_attr"] = inUserAttr
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodUserAttr() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["user_attr"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodUserDn(inUserDn string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["user_dn"] = inUserDn
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodUserDn() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["user_dn"] = nil
		o.postMap["attributes"] = val
	}
}

func WithLdapAuthMethodUserFilter(inUserFilter string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["user_filter"] = inUserFilter
		o.postMap["attributes"] = val
	}
}

func DefaultLdapAuthMethodUserFilter() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["user_filter"] = nil
		o.postMap["attributes"] = val
	}
}
