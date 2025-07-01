// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Protocol provides a listener and dial function that can be used to easily
// integrate this library into other applications. An application can wrap its
// incoming listener with an InterceptingListener from this package, which will
// handle the connection iff the incoming TLS NextProto value is one known by
// this library, and it can have its dial function use this package for dialing.
// Either a connection will be returned or a (possibly temporary) error; on the
// application side, it merely needs to check the negotiated protocol in the
// returned tls.Conn to see if it matches the defined authentication proto (a
// fetch connection will _always_ return a (temporary) error). If so, the node
// is successfully authenticated.
//
// Using this package is optional but encouraged when possible to avoid having
// to instrument logic directly within an app.
package protocol
