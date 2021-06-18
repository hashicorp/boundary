package event

import (
	"errors"
)

var (
	ErrInvalidParameter = errors.New("invalid parameter")
	ErrMaxRetries       = errors.New("too many retries")
	ErrIo               = errors.New("error during io operation")
	ErrRecordNotFound   = errors.New("record not found")
)
