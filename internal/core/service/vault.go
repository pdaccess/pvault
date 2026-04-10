package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/rs/zerolog/log"
)

// CreateVault initializes a new vault, registers the caller as its admin member,
// and appends an audit entry for the operation.
func (s *Impl) CreateVault(ctx context.Context, vaultID, userID uuid.UUID, userRootKey []byte) error {
	log.Info().Str("vault_id", vaultID.String()).Msg("creating vault")

	// 1. Ensure the vault does not already exist.
	existing, err := s.repo.GetMasterWrap(ctx, vaultID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("check vault existence: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("vault %s already exists", vaultID)
	}

	// 2. Generate vault key (Kv) and persist it wrapped by the service master key (Ks).
	kv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kv); err != nil {
		return fmt.Errorf("generate vault key: %w", err)
	}
	ks := s.crypto.GetServiceMasterKey()
	wrappedKv, nonce, err := s.crypto.Encrypt(kv, ks)
	if err != nil {
		return fmt.Errorf("wrap vault key: %w", err)
	}
	if err := s.repo.SaveMasterWrap(ctx, &domain.MasterWrap{
		VaultID:          vaultID,
		MasterWrappedKey: wrappedKv,
		Nonce:            nonce,
		UpdatedAt:        time.Now(),
	}); err != nil {
		return fmt.Errorf("save master wrap: %w", err)
	}

	// 3. Add the caller as the vault's admin member.
	if err := s.CreateMembership(ctx, userID, userID, vaultID, userRootKey, domain.AdminRole); err != nil {
		return fmt.Errorf("create admin membership: %w", err)
	}

	// 4. Record an audit entry for vault creation.
	return s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: vaultID,
		EventType:     domain.EventTypeCreateVault,
		ActorID:       userID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"vault_id": vaultID.String(),
			"user_id":  userID.String(),
			"role":     "admin",
		},
	})
}
