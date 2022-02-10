package cluster

import (
	// Enable tcp target support.
	_ "github.com/hashicorp/boundary/internal/servers/controller/handlers/targets/tcp"
	_ "github.com/hashicorp/boundary/internal/target/tcp"
)
