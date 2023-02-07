// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package proxy contains a collection of proxy handlers for the worker to call once a
// connection has been authorized. Each proxy handler should mark the connection as
// connected once the proxy has successfully been established.
package proxy
