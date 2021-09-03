package testhostplugin

import "github.com/hashicorp/boundary/plugin/proto"

// Implementation test.
var _ = proto.HostPluginServiceClient((*TestHostPlugin)(nil))
