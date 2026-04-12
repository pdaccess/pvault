package mock

import (
	"context"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
)

type mockDb struct {
	memberships map[uuid.UUID]map[uuid.UUID]*domain.Membership
	secrets     map[uuid.UUID]map[uuid.UUID]*domain.SecretValue
	masterWraps map[uuid.UUID]*domain.MasterWrap
	auditLogs   []*domain.AuditEntry
	checkouts   map[uuid.UUID]map[int]*domain.SecretCheckout
	identities  map[uuid.UUID]*domain.Identity
}

func (m *mockDb) SaveMembership(ctx context.Context, mem *domain.Membership) error {
	if m.memberships == nil {
		m.memberships = make(map[uuid.UUID]map[uuid.UUID]*domain.Membership)
	}
	if m.memberships[mem.UserID] == nil {
		m.memberships[mem.UserID] = make(map[uuid.UUID]*domain.Membership)
	}
	m.memberships[mem.UserID][mem.VaultID] = mem
	return nil
}

func (m *mockDb) GetMembership(ctx context.Context, userID, vaultID uuid.UUID) (*domain.Membership, error) {
	if m.memberships == nil {
		return nil, nil
	}
	vaults := m.memberships[userID]
	if vaults == nil {
		return nil, nil
	}
	return vaults[vaultID], nil
}

func (m *mockDb) ListVaultIDsByUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	if m.memberships == nil {
		return nil, nil
	}
	vaults := m.memberships[userID]
	if vaults == nil {
		return nil, nil
	}
	var ids []uuid.UUID
	for id := range vaults {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *mockDb) DeleteMembership(ctx context.Context, userID, vaultID uuid.UUID) error {
	if m.memberships != nil {
		if vaults := m.memberships[userID]; vaults != nil {
			delete(vaults, vaultID)
		}
	}
	return nil
}

func (m *mockDb) SaveSecret(ctx context.Context, s *domain.SecretValue) error {
	if m.secrets == nil {
		m.secrets = make(map[uuid.UUID]map[uuid.UUID]*domain.SecretValue)
	}
	if m.secrets[s.VaultID] == nil {
		m.secrets[s.VaultID] = make(map[uuid.UUID]*domain.SecretValue)
	}
	m.secrets[s.VaultID][s.ID] = s
	return nil
}

func (m *mockDb) GetSecretValue(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretValue, error) {
	if m.secrets == nil {
		return nil, nil
	}
	for _, vaultSecrets := range m.secrets {
		if s, ok := vaultSecrets[secretID]; ok {
			if version > 0 && s.Version != version {
				continue
			}
			return s, nil
		}
	}
	return nil, nil
}

func (m *mockDb) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID) (int, error) {
	if m.secrets == nil {
		return 0, nil
	}
	for _, vaultSecrets := range m.secrets {
		if s, ok := vaultSecrets[secretID]; ok {
			return s.Version, nil
		}
	}
	return 0, nil
}

func (m *mockDb) GetSecret(ctx context.Context, secretID uuid.UUID, version *int) (*domain.SecretValue, error) {
	if version == nil {
		v, err := m.GetLatestSecretVersion(ctx, secretID)
		if err != nil {
			return nil, err
		}
		version = &v
	}
	return m.GetSecretValue(ctx, secretID, *version)
}

func (m *mockDb) DeleteSecret(ctx context.Context, secretID uuid.UUID) error {
	if m.secrets != nil {
		for _, vaultSecrets := range m.secrets {
			delete(vaultSecrets, secretID)
		}
	}
	return nil
}

func (m *mockDb) GetUserSecretCapabilities(ctx context.Context, userID, secretID uuid.UUID) (*domain.UserSecretCapabilities, error) {
	return nil, domain.ErrNotFound
}

func (m *mockDb) SaveUserSecretCapabilities(ctx context.Context, caps *domain.UserSecretCapabilities) error {
	return nil
}

func (m *mockDb) SaveCheckout(ctx context.Context, checkout *domain.SecretCheckout) error {
	if m.checkouts == nil {
		m.checkouts = make(map[uuid.UUID]map[int]*domain.SecretCheckout)
	}
	if m.checkouts[checkout.SecretID] == nil {
		m.checkouts[checkout.SecretID] = make(map[int]*domain.SecretCheckout)
	}
	m.checkouts[checkout.SecretID][checkout.Version] = checkout
	return nil
}

func (m *mockDb) GetCheckout(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretCheckout, error) {
	if m.checkouts == nil {
		return nil, domain.ErrNotFound
	}
	if versions, ok := m.checkouts[secretID]; ok {
		if checkout, ok := versions[version]; ok {
			return checkout, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockDb) DeleteCheckout(ctx context.Context, secretID uuid.UUID, version int) error {
	if m.checkouts != nil {
		if versions, ok := m.checkouts[secretID]; ok {
			delete(versions, version)
		}
	}
	return nil
}

func (m *mockDb) SaveMasterWrap(ctx context.Context, mw *domain.MasterWrap) error {
	if m.masterWraps == nil {
		m.masterWraps = make(map[uuid.UUID]*domain.MasterWrap)
	}
	m.masterWraps[mw.VaultID] = mw
	return nil
}

func (m *mockDb) GetMasterWrap(ctx context.Context, vaultID uuid.UUID) (*domain.MasterWrap, error) {
	if m.masterWraps == nil {
		return nil, nil
	}
	return m.masterWraps[vaultID], nil
}

func (m *mockDb) AppendAuditLog(ctx context.Context, entry *domain.AuditEntry) error {
	m.auditLogs = append(m.auditLogs, entry)
	return nil
}

func (m *mockDb) GetLastAuditEntry(ctx context.Context) (*domain.AuditEntry, error) {
	if len(m.auditLogs) == 0 {
		return nil, nil
	}
	return m.auditLogs[len(m.auditLogs)-1], nil
}

func (m *mockDb) GetAuditEntries(ctx context.Context, start, limit int, userID, vaultID *uuid.UUID) ([]domain.AuditEntry, error) {
	var result []domain.AuditEntry
	for i := len(m.auditLogs) - 1; i >= 0 && len(result) < limit; i-- {
		entry := m.auditLogs[i]
		if userID != nil && entry.ActorID != *userID {
			continue
		}
		if vaultID != nil && entry.CorrelationID != *vaultID {
			continue
		}
		result = append(result, *entry)
	}
	if start > len(result) {
		return []domain.AuditEntry{}, nil
	}
	if start+limit > len(result) {
		limit = len(result) - start
	}
	return result[start : start+limit], nil
}

func (m *mockDb) SaveIdentity(ctx context.Context, identity *domain.Identity) error {
	if m.identities == nil {
		m.identities = make(map[uuid.UUID]*domain.Identity)
	}
	m.identities[identity.InternalID] = identity
	return nil
}

func (m *mockDb) GetIdentity(ctx context.Context, opts ...ports.IdentityOption) (*domain.Identity, error) {
	q := &ports.IdentityQuery{}
	for _, opt := range opts {
		opt(q)
	}

	for _, identity := range m.identities {
		if q.ID != nil && identity.InternalID != *q.ID {
			continue
		}
		if q.Provider != nil && identity.Provider != *q.Provider {
			continue
		}
		if q.ExternalID != nil && *q.ExternalID != "" {
			if identity.ExternalID == nil || *identity.ExternalID != *q.ExternalID {
				continue
			}
		}
		return identity, nil
	}
	return nil, domain.ErrNotFound
}

func New() ports.SecretRepository {
	return &mockDb{}
}
