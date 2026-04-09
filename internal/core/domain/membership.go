package domain

import (
	"time"

	"github.com/google/uuid"
)

type RoleType string

const (
	AdminRole = RoleType("admin")
	UserRole  = RoleType("user")
)

type Membership struct {
	UserID          uuid.UUID
	VaultID         uuid.UUID
	WrappedVaultKey []byte   // The Kv wrapped by the User's Ku
	Nonce           []byte   // IV for the key-wrapping
	Role            RoleType // e.g., "admin", "operator"
	UpdatedAt       time.Time
}
