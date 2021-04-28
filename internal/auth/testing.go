package auth

import (
	"context"

	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
)

// DisabledAuthTestContext is meant for testing, and uses a context that has auth checking entirely disabled
func DisabledAuthTestContext(iamRepoFn common.IamRepoFactory, scopeId string, opt ...Option) context.Context {
	reqInfo := RequestInfo{DisableAuthEntirely: true}
	opts := getOpts(opt...)
	reqInfo.scopeIdOverride = opts.withScopeId
	if reqInfo.scopeIdOverride == "" {
		reqInfo.scopeIdOverride = scopeId
	}
	reqInfo.userIdOverride = opts.withUserId
	if reqInfo.userIdOverride == "" {
		reqInfo.userIdOverride = "u_auth"
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	return NewVerifierContext(requestContext, nil, iamRepoFn, nil, nil, opts.withKms, reqInfo)
}
