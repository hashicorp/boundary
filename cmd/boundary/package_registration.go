package main

// Imports of packages for the side-effects of calling init functions.
// These packages call some form of a Register function to add in functionality.
import (
	// include worker tcp proxy
	_ "github.com/hashicorp/boundary/internal/servers/worker/proxy/tcp"
)
