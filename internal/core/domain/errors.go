package domain

import "errors"

var (
	ErrNotFound     = errors.New("no data found")
	ErrInvalidToken = errors.New("invalid token")
)
var (
	ErrNoMetadata                 = &AuthError{"no metadata in context"}
	ErrNoAuthorizationHeader      = &AuthError{"no authorization header"}
	ErrInvalidAuthorizationFormat = &AuthError{"invalid authorization format"}
)

type AuthError struct {
	msg string
}

func (e *AuthError) Error() string {
	return e.msg
}
