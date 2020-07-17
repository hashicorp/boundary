package auth

import "context"

// DisabledAuthTestContext is meant for testing, and uses a context that has auth checking entirely disabled
func DisabledAuthTestContext(opt ...TestOption) context.Context {
	reqInfo := RequestInfo{DisableAuthEntirely: true}
	opts := getOpts(opt...)
	reqInfo.scopeIdOverride = opts.withTestScopeId
	reqInfo.parentScopeIdOverride = opts.withTestParentScopeId
	return NewVerifierContext(context.Background(), nil, nil, nil, reqInfo)
}

func getOpts(opt ...TestOption) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type TestOption func(*options)

// options = how options are represented
type options struct {
	withTestScopeId       string
	withTestParentScopeId string
}

func getDefaultOptions() options {
	return options{
		withTestScopeId:       "",
		withTestParentScopeId: "",
	}
}

func WithTestScopeId(id string) TestOption {
	return func(o *options) {
		o.withTestScopeId = id
	}
}

func withTestParentScopeId(id string) TestOption {
	return func(o *options) {
		o.withTestParentScopeId = id
	}
}
