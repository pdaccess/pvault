package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
)

type VaultService interface {
	// Vault Operations
	CreateVault(ctx context.Context, vaultID, userID uuid.UUID, userRootKey []byte) error

	// Membership Operations
	CreateMembership(ctx context.Context, userID, vaultID uuid.UUID, ku []byte, role string, caps []string) error
	ListAuthorizedVaults(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	GetMembershipDetails(ctx context.Context, userID, vaultID uuid.UUID) (*domain.Membership, error)

	// Secret Operations
	ProtectSecret(ctx context.Context, callerID, secretID, vaultID uuid.UUID, plaintext string) error
	UncoverSecret(ctx context.Context, callerID, secretID, vaultID uuid.UUID, action string) (string, error)
	DeleteSecret(ctx context.Context, secretID uuid.UUID) error

	// System & Audit
	RecordAudit(ctx context.Context, entry *domain.AuditEntry) error
	RotateVaultKey(ctx context.Context, vaultID uuid.UUID) error
}
