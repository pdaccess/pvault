package domain

import (
	"slices"
	"time"

	"github.com/google/uuid"
)

type Membership struct {
	UserID          uuid.UUID
	VaultID         uuid.UUID
	WrappedVaultKey []byte   // The Kv wrapped by the User's Ku
	Nonce           []byte   // IV for the key-wrapping
	Role            string   // e.g., "admin", "operator"
	Capabilities    []string // e.g., ["see", "connect", "change"]
	UpdatedAt       time.Time
}

// CanExecute is a domain method to verify functional permissions
func (m *Membership) CanExecute(capability string) bool {
	return slices.Contains(m.Capabilities, capability)
}
