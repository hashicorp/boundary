package subtypes

import "fmt"

type UnknownSubtypeIDError struct {
	ID string
}

func (e *UnknownSubtypeError) Error() string {
	return "unknown subtype in ID: " + e.ID
}
