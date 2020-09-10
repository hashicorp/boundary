package auth

import "context"

// DisabledAuthTestContext is meant for testing, and uses a context that has auth checking entirely disabled
func DisabledAuthTestContext(opt ...Option) context.Context {
	reqInfo := RequestInfo{DisableAuthEntirely: true}
	opts := getOpts(opt...)
	reqInfo.scopeIdOverride = opts.withScopeId
	reqInfo.userIdOverride = opts.withUserId
	return NewVerifierContext(context.Background(), nil, nil, nil, nil, opts.withKms, reqInfo)
}
