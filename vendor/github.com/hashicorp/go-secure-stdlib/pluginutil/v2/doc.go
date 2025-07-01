// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

/*
Package pluginutil provides common functions to make it easier to load plugins,
especially if they can be either instantiated in memory or implemented as
go-plugin plugins.

The package takes care of the actual building of the plugin map and execution of
the plugins.

The general flow is that BuildPluginMap is called with the various plugin
sources, which gives back a map of plugin information. Program-side validation
logic can then be used to decide whether or not to proceed, e.g. "if a certain
plugin is not available after parsing sources, quit".

The desired plugin information can then be sent to the CreatePlugin function,
along with potentially additional options, such as a SecureConfig section. This
function returns an interface that either represents a go-plugin client or a
direct Go interface. The calling code can do a type switch to figure out which
it is, dispense the plugin if needed, and return the interface back to the
caller.

For an example of usage, see the kms.go file in the configutil
package in this repository.
*/

package pluginutil
