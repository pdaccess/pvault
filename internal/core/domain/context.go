package domain

import "github.com/google/uuid"

type contextKey int

const (
	UserTokenIn contextKey = iota
	ContextKeyUserID
	ContextKeyUserRootKey
)

// UserClaims holds the parsed JWT claims for the authenticated caller.
type UserClaims struct {
	UserID      uuid.UUID
	UserRootKey []byte
}
