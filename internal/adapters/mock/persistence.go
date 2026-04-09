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

func (m *mockDb) GetSecretValue(ctx context.Context, secretID uuid.UUID) (*domain.SecretValue, error) {
	if m.secrets == nil {
		return nil, nil
	}
	for _, vaultSecrets := range m.secrets {
		if s, ok := vaultSecrets[secretID]; ok {
			return s, nil
		}
	}
	return nil, nil
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

func New() ports.SecretRepository {
	return &mockDb{}
}
