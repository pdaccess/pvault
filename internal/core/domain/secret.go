package domain

import (
	"time"

	"github.com/google/uuid"
)

type SecretValue struct {
	ID         uuid.UUID
	VaultID    uuid.UUID
	Ciphertext []byte // The actual data encrypted by DEK
	WrappedDEK []byte // The DEK wrapped by Vault Key (Kv)
	Nonce      []byte // IV for the ciphertext
	Version    int
	UpdatedAt  time.Time
}

type MasterWrap struct {
	VaultID          uuid.UUID
	MasterWrappedKey []byte // The Kv wrapped by Service Master Key (Ks)
	Nonce            []byte
	UpdatedAt        time.Time
}
