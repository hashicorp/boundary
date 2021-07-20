package plugin

// CurrentProtocolVersion represents the current protocol version
// expected by Boundary.
const CurrentProtocolVersion = 1

// MagicCookieKey is the magic cookie key used by Boundary. Plugins
// need to be able to serve this in order to identify them as
// Boundary plugins.
const MagicCookieKey = "BOUNDARY_PLUGIN"

// MagicCookieValue is the magic cookie value used by Boundary. Plugins
// need to be able to serve this in order to identify them as
// Boundary plugins.
const MagicCookieValue = "18996A91-0E0C-466F-8E92-32A694989630"
