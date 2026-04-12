package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pdaccess/pvault/internal/core/domain"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// --- Membership Operations ---

func (s *Impl) CreateMembership(ctx context.Context, callerID, userID, vaultID uuid.UUID, ku []byte, role domain.VaultRole) error {
	log.Info().Str("vault_id", vaultID.String()).Str("user_id", userID.String()).Str("role", string(role)).Msg("adding member")

	// Allow caller to self-register as admin (for vault creation)
	isCreatingOwnAdmin := callerID == userID && role == domain.AdminRole

	// 1. Verify caller is admin of the vault (unless self-registering as admin)
	if !isCreatingOwnAdmin {
		callerMem, err := s.repo.GetMembership(ctx, callerID, vaultID)
		if err != nil {
			return err
		}
		if callerMem.Role != domain.AdminRole {
			return errors.New("unauthorized: only admin users can add membership")
		}
	}

	// 2. Fetch Master Wrap to get the Vault Key (Kv).
	//    The vault must be created via CreateVault before members can be added.
	master, err := s.repo.GetMasterWrap(ctx, vaultID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("get master wrap: %w", err)
	}
	if master == nil {
		return fmt.Errorf("vault %s not found: call CreateVault first", vaultID)
	}

	// 2. Unwrap Kv using Service Master Key (Ks)
	ks := s.crypto.GetServiceMasterKey()
	kv, err := s.crypto.UnwrapKey(master.MasterWrappedKey, ks, master.Nonce)
	if err != nil {
		return errors.New("failed to unwrap master vault key")
	}

	// 3. Wrap Kv with the User's Root Key (Ku)
	wrappedKv, nonce, err := s.crypto.Encrypt(kv, ku)
	if err != nil {
		return err
	}

	mem := &domain.Membership{
		UserID:          userID,
		VaultID:         vaultID,
		WrappedVaultKey: wrappedKv,
		Nonce:           nonce,
		Role:            role,
		UpdatedAt:       time.Now(),
	}

	if err := s.repo.SaveMembership(ctx, mem); err != nil {
		return err
	}

	// 4. Record audit entry for the membership creation.
	return s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: vaultID,
		EventType:     domain.EventTypeAddMember,
		ActorID:       userID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"vault_id": vaultID.String(),
			"user_id":  userID.String(),
			"role":     role,
		},
	})
}

func (s *Impl) ListAuthorizedVaults(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	return s.repo.ListVaultIDsByUser(ctx, userID)
}

func (s *Impl) getMembershipDetails(ctx context.Context, userID, vaultID uuid.UUID) (*domain.Membership, error) {
	return s.repo.GetMembership(ctx, userID, vaultID)
}

func (s *Impl) RotateVaultKey(ctx context.Context, vaultID uuid.UUID) error {
	// Complex: Requires re-wrapping all secrets in the vault with a new Kv
	// 1. Generate new Kv
	// 2. Re-wrap MasterWrap with Ks
	// 3. Loop through all secret_values, unwrap with old Kv, re-wrap with new Kv
	// 4. Update memberships
	return errors.New("not implemented: rotation requires batch transaction")
}
