// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package event

// Define a set of common keys and values to use in event payload maps.  Having
// and using a common set will allow operators to more easily define event
// filters.
const (
	ServerName    string = "server_name" // ServerName: event source server name
	ServerAddress string = "server_addr" // ServerAddress: event source server address
)
