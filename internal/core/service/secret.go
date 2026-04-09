package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pdaccess/pvault/internal/core/domain"

	"github.com/google/uuid"
)

// --- Secret Operations ---

func (s *Impl) ProtectSecret(ctx context.Context, callerID, secretID, vaultID uuid.UUID, plaintext string) error {
	// 1. Get Kv via Master Wrap.
	//    The vault must be created via CreateVault before secrets can be stored.
	master, err := s.repo.GetMembership(ctx, callerID, vaultID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if master == nil {
		return fmt.Errorf("vault %s not found: call CreateVault first", vaultID)
	}
	ku, err := s.crypto.ExtractUserRootKey(ctx)
	if err != nil {
		return err
	}
	kv, err := s.crypto.UnwrapKey(master.WrappedVaultKey, ku, master.Nonce)
	if err != nil {
		return err
	}

	// 2. Generate random DEK
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return err
	}

	// 3. Encrypt data with DEK
	ciphertext, nonce, err := s.crypto.Encrypt([]byte(plaintext), dek)
	if err != nil {
		return err
	}

	// 4. Wrap DEK with Kv; prepend the random nonce to wrappedDEK so that
	//    UncoverSecret can extract it without a separate DB column.
	wrappedDEK, dekNonce, err := s.crypto.Encrypt(dek, kv)
	if err != nil {
		return err
	}
	storedWrappedDEK := append(dekNonce, wrappedDEK...) //nolint:gocritic

	secret := &domain.SecretValue{
		ID:         secretID,
		VaultID:    vaultID,
		Ciphertext: ciphertext,
		WrappedDEK: storedWrappedDEK,
		Nonce:      nonce, // nonce for the plaintext ciphertext
		Version:    1,
		UpdatedAt:  time.Now(),
	}

	if err := s.repo.SaveSecret(ctx, secret); err != nil {
		return err
	}

	// 5. Record audit entry for secret protection.
	return s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: vaultID,
		EventType:     "protect_secret",
		ActorID:       secretID,
		ActionStatus:  "success",
		Payload: map[string]any{
			"secret_id": secretID.String(),
			"vault_id":  vaultID.String(),
		},
	})
}

func (s *Impl) UncoverSecret(ctx context.Context, callerID, secretID, vaultID uuid.UUID, action string) (string, error) {
	// 1. RBAC Check (Capabilities)
	mem, err := s.repo.GetMembership(ctx, callerID, vaultID)
	if err != nil || !mem.CanExecute(action) {
		return "", errors.New("unauthorized: insufficient capabilities")
	}

	// 2. Fetch Secret
	val, err := s.repo.GetSecretValue(ctx, secretID)
	if err != nil {
		return "", err
	}

	// 3. The Unwrap Chain
	ku, _ := s.crypto.ExtractUserRootKey(ctx)
	kv, err := s.crypto.UnwrapKey(mem.WrappedVaultKey, ku, mem.Nonce)
	if err != nil {
		return "", errors.New("crypto failure: vault key unwrap")
	}

	// WrappedDEK is stored as [12-byte nonce || encrypted DEK] — see ProtectSecret.
	const gcmNonceSize = 12
	if len(val.WrappedDEK) < gcmNonceSize {
		return "", errors.New("crypto failure: wrapped DEK too short")
	}
	dekNonce := val.WrappedDEK[:gcmNonceSize]
	wrappedDEKData := val.WrappedDEK[gcmNonceSize:]

	dek, err := s.crypto.UnwrapKey(wrappedDEKData, kv, dekNonce)
	if err != nil {
		return "", errors.New("crypto failure: dek unwrap")
	}

	plaintext, err := s.crypto.Decrypt(val.Ciphertext, dek, val.Nonce)
	if err != nil {
		return "", err
	}

	// 4. Record audit entry for secret access.
	if auditErr := s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: vaultID,
		EventType:     "uncover_secret",
		ActorID:       secretID,
		ActionStatus:  "success",
		Payload: map[string]any{
			"secret_id": secretID.String(),
			"vault_id":  vaultID.String(),
			"action":    action,
		},
	}); auditErr != nil {
		return "", auditErr
	}

	return string(plaintext), nil
}

func (s *Impl) DeleteSecret(ctx context.Context, secretID uuid.UUID) error {
	if err := s.repo.DeleteSecret(ctx, secretID); err != nil {
		return err
	}

	// Record audit entry for secret deletion.
	return s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: secretID,
		EventType:     "delete_secret",
		ActorID:       secretID,
		ActionStatus:  "success",
		Payload: map[string]any{
			"secret_id": secretID.String(),
		},
	})
}
