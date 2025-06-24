// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

// Expose functions for use in tests.
var (
	AllocTargetView                        = allocTargetView
	TargetsViewDefaultTable                = targetsViewDefaultTable
	ProxyCertRewrapFn                      = proxyCertRewrapFn
	ProxyAliasCertRewrapFn                 = proxyAliasCertRewrapFn
	AllocTargetProxyCertificate            = allocTargetProxyCertificate
	AllocTargetAliasProxyCertificate       = allocTargetAliasProxyCertificate
	FetchTargetProxyServerCertificate      = fetchTargetProxyServerCertificate
	FetchTargetAliasProxyServerCertificate = fetchTargetAliasProxyServerCertificate
)
