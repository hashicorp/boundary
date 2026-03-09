// Copyright IBM Corp. 2020, 2025
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
