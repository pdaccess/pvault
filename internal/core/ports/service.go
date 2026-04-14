package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
)

type VaultService interface {
	// Identity & Authentication
	Authorize(ctx context.Context, provider domain.IdentityProvider, username, password, externalID string, transitPubKey []byte) (string, string, error)
	CreateUser(ctx context.Context, username, password, externalID string, provider domain.IdentityProvider, transitPubKey []byte) (string, string, error)
	ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	// Vault Operations
	CreateVault(ctx context.Context, vaultID, userID uuid.UUID, userRootKey []byte) error

	// Membership Operations
	CreateMembership(ctx context.Context, callerID, userID, vaultID uuid.UUID, ku []byte, role domain.VaultRole) error
	ListAuthorizedVaults(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)

	// Secret Operations
	ProtectSecret(ctx context.Context, callerID, secretID, vaultID uuid.UUID, plaintext string, capabilities domain.Capabilities) error
	UncoverSecret(ctx context.Context, callerID, secretID uuid.UUID, action domain.Capability, version *int) (string, int, error)
	DeleteSecret(ctx context.Context, secretID uuid.UUID) error
	UpdateSecretCapabilities(ctx context.Context, callerID, targetUserID, secretID uuid.UUID, capabilities domain.Capabilities) error

	// System & Audit
	RecordAudit(ctx context.Context, entry *domain.AuditEntry) error
	GetAuditEntries(ctx context.Context, start, limit int, userID, vaultID *uuid.UUID) ([]domain.AuditEntry, error)
}
