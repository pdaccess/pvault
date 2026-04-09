package pg

import (
	"context"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

var (
	createSchema = `
-- -----------------------------------------------------
-- PVault: The Hardened Cryptographic Data Plane
-- -----------------------------------------------------

CREATE SCHEMA IF NOT EXISTS vault;

-- 1. Vault Membership (Cryptographic Access + RBAC)
-- Key storage and permission enforcement.
CREATE TABLE IF NOT EXISTS vault.memberships (
    user_id            UUID NOT NULL,
    vault_id           UUID NOT NULL,
    wrapped_vault_key  BYTEA NOT NULL, 
    nonce              BYTEA NOT NULL, 
    role               TEXT NOT NULL DEFAULT 'user',
    capabilities       JSONB NOT NULL DEFAULT '["see", "connect"]',
    updated_at         TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, vault_id)
);

-- 2. Secret Values (Blinded Data)
-- Storage for encrypted payloads.
CREATE TABLE IF NOT EXISTS vault.secret_values (
    id                 UUID PRIMARY KEY,
    vault_id           UUID NOT NULL,
    ciphertext         BYTEA NOT NULL, 
    wrapped_dek        BYTEA NOT NULL, 
    nonce              BYTEA NOT NULL, 
    version            INT DEFAULT 1,
    updated_at         TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Vault Master Recovery (System-Level Backup)
-- Backup keys wrapped by the Service Master Key (Ks).
CREATE TABLE IF NOT EXISTS vault.master_wraps (
    vault_id           UUID PRIMARY KEY,
    master_wrapped_key BYTEA NOT NULL, 
    nonce              BYTEA NOT NULL, 
    updated_at         TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Unified Audit Chain (HMAC-Signed History)
-- Immutable history with HMAC chaining for integrity.
CREATE TABLE IF NOT EXISTS vault.audit_chain (
    id                 BIGSERIAL PRIMARY KEY,
    source_service     TEXT NOT NULL,    
    correlation_id     UUID NOT NULL,    
    event_type         TEXT NOT NULL,    
    actor_id           UUID,             
    action_status      TEXT NOT NULL,    
    payload            JSONB,            
    prev_hmac          BYTEA,            
    curr_hmac          BYTEA NOT NULL,   
    updated_at         TIMESTAMPTZ DEFAULT NOW() 
);

-- -----------------------------------------------------
-- Indexes for performance
-- -----------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_vault_membership_user ON vault.memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_vault_secrets_vault ON vault.secret_values(vault_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON vault.audit_chain(correlation_id);`
)

func CreateSchema(ctx context.Context, connectionStr string) error {
	db, err := sqlx.Connect("pgx", connectionStr)
	if err != nil {
		return fmt.Errorf("sql connect: %w", err)
	}

	_, err = db.ExecContext(ctx, createSchema)

	if err != nil {
		return fmt.Errorf("createKvTable: %w", err)
	}

	return nil
}
