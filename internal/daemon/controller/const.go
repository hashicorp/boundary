// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controller

const (
	// userAgentKey is the key used to identify the user agent in the request header
	userAgentKey = "User-Agent"

	// userAgentProductKey and userAgentProductVersionKey are used to define user agent in the observation events
	userAgentProductKey        = "user_agent_product"
	userAgentProductVersionKey = "user_agent_product_version"
)
