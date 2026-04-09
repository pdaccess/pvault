package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
)

type SecretRepository interface {
	// Membership Storage
	SaveMembership(ctx context.Context, m *domain.Membership) error
	GetMembership(ctx context.Context, userID, vaultID uuid.UUID) (*domain.Membership, error)
	ListVaultIDsByUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	DeleteMembership(ctx context.Context, userID, vaultID uuid.UUID) error

	// Secret Storage
	SaveSecret(ctx context.Context, s *domain.SecretValue) error
	GetSecretValue(ctx context.Context, secretID uuid.UUID) (*domain.SecretValue, error)
	DeleteSecret(ctx context.Context, secretID uuid.UUID) error

	// Master/Recovery Storage
	SaveMasterWrap(ctx context.Context, mw *domain.MasterWrap) error
	GetMasterWrap(ctx context.Context, vaultID uuid.UUID) (*domain.MasterWrap, error)

	// Audit Storage
	AppendAuditLog(ctx context.Context, entry *domain.AuditEntry) error
	GetLastAuditEntry(ctx context.Context) (*domain.AuditEntry, error)
}
