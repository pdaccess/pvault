package pg

import (
	"time"

	"github.com/google/uuid"
)

type VaultMembership struct {
	UserID          uuid.UUID `db:"user_id" json:"user_id"`
	VaultID         uuid.UUID `db:"vault_id" json:"vault_id"`
	WrappedVaultKey []byte    `db:"wrapped_vault_key" json:"-"` // Never expose keys in JSON
	Nonce           []byte    `db:"nonce" json:"-"`
	Role            string    `db:"role" json:"role"`
	Capabilities    []string  `db:"capabilities" json:"capabilities"`
	UpdatedAt       time.Time `db:"updated_at" json:"updated_at"`
}

type SecretValue struct {
	ID         uuid.UUID `db:"id" json:"id"`
	VaultID    uuid.UUID `db:"vault_id" json:"vault_id"`
	Ciphertext []byte    `db:"ciphertext" json:"-"`
	WrappedDEK []byte    `db:"wrapped_dek" json:"-"`
	Nonce      []byte    `db:"nonce" json:"-"`
	Version    int       `db:"version" json:"version"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

type MasterWrap struct {
	VaultID          uuid.UUID `db:"vault_id" json:"vault_id"`
	MasterWrappedKey []byte    `db:"master_wrapped_key" json:"-"`
	Nonce            []byte    `db:"nonce" json:"-"`
	UpdatedAt        time.Time `db:"updated_at" json:"updated_at"`
}

type AuditEntry struct {
	ID            int64     `db:"id" json:"id"`
	SourceService string    `db:"source_service" json:"source_service"`
	CorrelationID uuid.UUID `db:"correlation_id" json:"correlation_id"`
	EventType     string    `db:"event_type" json:"event_type"`
	ActorID       uuid.UUID `db:"actor_id" json:"actor_id"`
	ActionStatus  string    `db:"action_status" json:"action_status"`
	Payload       []byte    `db:"payload" json:"payload"` // Use []byte for JSONB
	PrevHMAC      []byte    `db:"prev_hmac" json:"-"`
	CurrHMAC      []byte    `db:"curr_hmac" json:"-"`
	UpdatedAt     time.Time `db:"updated_at" json:"updated_at"`
}
