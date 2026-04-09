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

func (s *Impl) ProtectSecret(ctx context.Context, callerID, secretID, vaultID uuid.UUID, plaintext string, defaultCapabilities domain.Capabilities) error {
	if err := defaultCapabilities.Validate(); err != nil {
		return fmt.Errorf("invalid capabilities: %w", err)
	}

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
		ID:            secretID,
		VaultID:       vaultID,
		CreatorUserID: callerID,
		Ciphertext:    ciphertext,
		WrappedDEK:    storedWrappedDEK,
		Nonce:         nonce,
		Version:       1,
		UpdatedAt:     time.Now(),
	}

	if err := s.repo.SaveSecret(ctx, secret); err != nil {
		return err
	}

	// 5. Grant default capabilities to the caller
	if len(defaultCapabilities) == 0 {
		defaultCapabilities = domain.Capabilities{domain.CapSee, domain.CapConnect}
	}
	if err := s.repo.SaveUserSecretCapabilities(ctx, &domain.UserSecretCapabilities{
		UserID:       callerID,
		SecretID:     secretID,
		Capabilities: defaultCapabilities,
		UpdatedAt:    time.Now(),
	}); err != nil {
		return err
	}

	// 6. Record audit entry for secret protection.
	return s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: vaultID,
		EventType:     domain.EventTypeProtectSecret,
		ActorID:       secretID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"secret_id": secretID.String(),
			"vault_id":  vaultID.String(),
		},
	})
}

func (s *Impl) UncoverSecret(ctx context.Context, callerID, secretID uuid.UUID, action string) (string, error) {
	// 1. Check user-specific capabilities on the secret
	userCaps, err := s.repo.GetUserSecretCapabilities(ctx, callerID, secretID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "", errors.New("unauthorized: user has no capabilities on secret")
		}
		return "", err
	}
	if !userCaps.CanExecute(action) {
		return "", errors.New("unauthorized: action not permitted")
	}

	// 2. Fetch Secret
	val, err := s.repo.GetSecretValue(ctx, secretID)
	if err != nil {
		return "", err
	}

	// 3. Get membership to unwrap vault key
	mem, err := s.repo.GetMembership(ctx, callerID, val.VaultID)
	if err != nil {
		return "", err
	}

	// 4. The Unwrap Chain
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
		CorrelationID: val.VaultID,
		EventType:     domain.EventTypeUncoverSecret,
		ActorID:       secretID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"secret_id": secretID.String(),
			"vault_id":  val.VaultID.String(),
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
		EventType:     domain.EventTypeDeleteSecret,
		ActorID:       secretID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"secret_id": secretID.String(),
		},
	})
}

func (s *Impl) UpdateSecretCapabilities(ctx context.Context, callerID, targetUserID, secretID uuid.UUID, capabilities domain.Capabilities) error {
	if err := capabilities.Validate(); err != nil {
		return fmt.Errorf("invalid capabilities: %w", err)
	}

	// 1. Fetch secret to get the vault_id
	val, err := s.repo.GetSecretValue(ctx, secretID)
	if err != nil {
		return err
	}
	vaultID := val.VaultID

	// 2. Verify caller is a member of the vault
	mem, err := s.repo.GetMembership(ctx, callerID, vaultID)
	if err != nil {
		return err
	}
	if mem == nil {
		return errors.New("not a member of this vault")
	}

	// 3. Check if caller has admin role (only admins can change capabilities)
	if mem.Role != "admin" {
		return errors.New("unauthorized: only admins can update secret capabilities")
	}

	// 4. Update user-specific capabilities in repository
	if err := s.repo.SaveUserSecretCapabilities(ctx, &domain.UserSecretCapabilities{
		UserID:       targetUserID,
		SecretID:     secretID,
		Capabilities: capabilities,
		UpdatedAt:    time.Now(),
	}); err != nil {
		return err
	}

	// 5. Record audit entry for capability update.
	return s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: vaultID,
		EventType:     domain.EventTypeUpdateSecretCapabilities,
		ActorID:       callerID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"secret_id":    secretID.String(),
			"target_user":  targetUserID.String(),
			"capabilities": capabilities,
		},
	})
}
