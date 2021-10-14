package db

import (
	// import for init side-effects to include migrations
	_ "github.com/hashicorp/boundary/internal/db/schema/migrations/oss"
)
