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

	// 5. Determine version: always auto-increment from latest
	latestVersion := 0
	if latest, err := s.repo.GetSecret(ctx, secretID, nil); err == nil {
		latestVersion = latest.Version

		// Check write capability for update
		callerCaps, err := s.repo.GetUserSecretCapabilities(ctx, callerID, secretID)
		if err != nil {
			return err
		}
		if !callerCaps.CanExecute(string(domain.CapWrite)) {
			return errors.New("unauthorized: write capability required to update secret")
		}
	}
	newVersion := latestVersion + 1

	secret := &domain.SecretValue{
		ID:            secretID,
		VaultID:       vaultID,
		CreatorUserID: callerID,
		Ciphertext:    ciphertext,
		WrappedDEK:    storedWrappedDEK,
		Nonce:         nonce,
		Version:       newVersion,
		UpdatedAt:     time.Now(),
	}

	if err := s.repo.SaveSecret(ctx, secret); err != nil {
		return err
	}

	// 6. Grant default capabilities only for new secrets
	if latestVersion == 0 {
		if len(defaultCapabilities) == 0 {
			defaultCapabilities = domain.ValidCapabilities
		}
		if err := s.repo.SaveUserSecretCapabilities(ctx, &domain.UserSecretCapabilities{
			UserID:       callerID,
			SecretID:     secretID,
			Capabilities: defaultCapabilities,
			UpdatedAt:    time.Now(),
		}); err != nil {
			return err
		}
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

func (s *Impl) UncoverSecret(ctx context.Context, callerID, secretID uuid.UUID, action domain.Capability, version *int) (string, int, error) {
	userCaps, err := s.repo.GetUserSecretCapabilities(ctx, callerID, secretID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "", 0, errors.New("unauthorized: user has no capabilities on secret")
		}
		return "", 0, err
	}
	if !userCaps.CanExecute(string(action)) {
		return "", 0, errors.New("unauthorized: action not permitted")
	}

	var versionToFetch int
	if version == nil {
		latest, err := s.repo.GetSecret(ctx, secretID, nil)
		if err != nil {
			return "", 0, err
		}
		versionToFetch = latest.Version
	} else {
		versionToFetch = *version
	}

	val, err := s.repo.GetSecret(ctx, secretID, &versionToFetch)
	if err != nil {
		return "", 0, err
	}

	if action == domain.CapCheck {
		checkout, err := s.repo.GetCheckout(ctx, secretID, versionToFetch)
		if err == nil && checkout.UserID == callerID && !checkout.IsExpired() {
			if err := s.repo.DeleteCheckout(ctx, secretID, versionToFetch); err != nil {
				s.RecordAudit(ctx, &domain.AuditEntry{
					SourceService: "pvault",
					CorrelationID: val.VaultID,
					EventType:     domain.EventTypeCheckOut,
					ActorID:       callerID,
					ActionStatus:  "success",
					Payload: domain.AuditPayload{
						"secret_id": secretID.String(),
						"version":   versionToFetch,
					},
				})
				return "", 0, err
			}
			s.RecordAudit(ctx, &domain.AuditEntry{
				SourceService: "pvault",
				CorrelationID: val.VaultID,
				EventType:     domain.EventTypeCheckOut,
				ActorID:       callerID,
				ActionStatus:  "success",
				Payload: domain.AuditPayload{
					"secret_id": secretID.String(),
					"version":   versionToFetch,
				},
			})
			return "", versionToFetch, nil
		}

		if err == nil && checkout.UserID != callerID && !checkout.IsExpired() {
			return "", 0, errors.New("secret checked out by another user")
		}

		checkout = &domain.SecretCheckout{
			SecretID:     secretID,
			Version:      versionToFetch,
			UserID:       callerID,
			CheckedOutAt: time.Now(),
		}
		if err := s.repo.SaveCheckout(ctx, checkout); err != nil {
			return "", 0, err
		}
		s.RecordAudit(ctx, &domain.AuditEntry{
			SourceService: "pvault",
			CorrelationID: val.VaultID,
			EventType:     domain.EventTypeCheckIn,
			ActorID:       callerID,
			ActionStatus:  "success",
			Payload: domain.AuditPayload{
				"secret_id": secretID.String(),
				"version":   versionToFetch,
			},
		})
		return "", versionToFetch, nil
	}

	checkout, err := s.repo.GetCheckout(ctx, secretID, versionToFetch)
	if err == nil && !checkout.IsExpired() {
		if checkout.UserID != callerID {
			return "", 0, errors.New("secret checked out by another user")
		}
	}
	if checkout != nil && checkout.IsExpired() {
		s.repo.DeleteCheckout(ctx, secretID, versionToFetch)
	}

	mem, err := s.repo.GetMembership(ctx, callerID, val.VaultID)
	if err != nil {
		return "", 0, err
	}

	ku, _ := s.crypto.ExtractUserRootKey(ctx)
	kv, err := s.crypto.UnwrapKey(mem.WrappedVaultKey, ku, mem.Nonce)
	if err != nil {
		return "", 0, errors.New("crypto failure: vault key unwrap")
	}

	const gcmNonceSize = 12
	if len(val.WrappedDEK) < gcmNonceSize {
		return "", 0, errors.New("crypto failure: wrapped DEK too short")
	}
	dekNonce := val.WrappedDEK[:gcmNonceSize]
	wrappedDEKData := val.WrappedDEK[gcmNonceSize:]

	dek, err := s.crypto.UnwrapKey(wrappedDEKData, kv, dekNonce)
	if err != nil {
		return "", 0, errors.New("crypto failure: dek unwrap")
	}

	plaintext, err := s.crypto.Decrypt(val.Ciphertext, dek, val.Nonce)
	if err != nil {
		return "", 0, err
	}

	s.RecordAudit(ctx, &domain.AuditEntry{
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
	})

	return string(plaintext), val.Version, nil
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

	// 1. Fetch latest secret to get the vault_id
	latest, err := s.repo.GetSecret(ctx, secretID, nil)
	if err != nil {
		return err
	}
	vaultID := latest.VaultID

	// 2. Verify caller is a member of the vault
	mem, err := s.repo.GetMembership(ctx, callerID, vaultID)
	if err != nil {
		return err
	}
	if mem == nil {
		return errors.New("not a member of this vault")
	}

	// 3. Check if caller has mngt capability on the secret
	callerCaps, err := s.repo.GetUserSecretCapabilities(ctx, callerID, secretID)
	if err != nil {
		return err
	}
	if !callerCaps.CanExecute(string(domain.CapMngt)) {
		return errors.New("unauthorized: mngt capability required")
	}

	// 5. Update user-specific capabilities in repository
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
