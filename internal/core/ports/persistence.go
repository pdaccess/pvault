package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
)

type IdentityQuery struct {
	ID         *uuid.UUID
	Provider   *domain.IdentityProvider
	ExternalID *string
	Username   *string
}

type IdentityOption func(*IdentityQuery)

func WithIdentityID(id uuid.UUID) IdentityOption {
	return func(q *IdentityQuery) { q.ID = &id }
}

func WithProvider(p domain.IdentityProvider) IdentityOption {
	return func(q *IdentityQuery) { q.Provider = &p }
}

func WithExternalID(id string) IdentityOption {
	return func(q *IdentityQuery) { q.ExternalID = &id }
}

func WithUsername(username string) IdentityOption {
	return func(q *IdentityQuery) { q.Username = &username }
}

type SecretRepository interface {
	// Membership Storage
	SaveMembership(ctx context.Context, m *domain.Membership) error
	GetMembership(ctx context.Context, userID, vaultID uuid.UUID) (*domain.Membership, error)
	ListVaultIDsByUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	DeleteMembership(ctx context.Context, userID, vaultID uuid.UUID) error

	// Secret Storage
	SaveSecret(ctx context.Context, s *domain.SecretValue) error
	GetSecret(ctx context.Context, secretID uuid.UUID, version *int) (*domain.SecretValue, error)
	DeleteSecret(ctx context.Context, secretID uuid.UUID) error

	// User-Secret Capabilities Storage
	GetUserSecretCapabilities(ctx context.Context, userID, secretID uuid.UUID) (*domain.UserSecretCapabilities, error)
	SaveUserSecretCapabilities(ctx context.Context, caps *domain.UserSecretCapabilities) error

	// Secret Checkouts (Check-in/Check-out for exclusive access)
	SaveCheckout(ctx context.Context, checkout *domain.SecretCheckout) error
	GetCheckout(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretCheckout, error)
	DeleteCheckout(ctx context.Context, secretID uuid.UUID, version int) error

	// Master/Recovery Storage
	SaveMasterWrap(ctx context.Context, mw *domain.MasterWrap) error
	GetMasterWrap(ctx context.Context, vaultID uuid.UUID) (*domain.MasterWrap, error)

	// Audit Storage
	AppendAuditLog(ctx context.Context, entry *domain.AuditEntry) error
	GetLastAuditEntry(ctx context.Context) (*domain.AuditEntry, error)
	GetAuditEntries(ctx context.Context, start, limit int, userID, vaultID *uuid.UUID) ([]domain.AuditEntry, error)

	// Identity Storage
	SaveIdentity(ctx context.Context, identity *domain.Identity) error
	GetIdentity(ctx context.Context, opts ...IdentityOption) (*domain.Identity, error)
}
