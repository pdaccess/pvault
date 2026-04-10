package domain

import (
	"time"

	"github.com/google/uuid"
)

type VaultRole string

const (
	AdminRole = VaultRole("admin")
	UserRole  = VaultRole("user")
)

type Membership struct {
	UserID          uuid.UUID
	VaultID         uuid.UUID
	WrappedVaultKey []byte    // The Kv wrapped by the User's Ku
	Nonce           []byte    // IV for the key-wrapping
	Role            VaultRole // e.g., "admin", "operator"
	UpdatedAt       time.Time
}
