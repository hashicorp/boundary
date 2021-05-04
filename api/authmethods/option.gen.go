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
