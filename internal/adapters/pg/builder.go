package pg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/rs/zerolog/log"
)

type PgPersistence struct {
	db *sqlx.DB
}

func New(connectionStr string) (ports.SecretRepository, error) {
	log.Info().Msg("connecting to PostgreSQL...")
	db, err := sqlx.Connect("pgx", connectionStr)
	if err != nil {
		return nil, fmt.Errorf("connection: %w", err)
	}
	log.Info().Msg("PostgreSQL connection established")

	log.Info().Msg("initializing database schema...")
	if err := CreateSchema(context.Background(), connectionStr); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	log.Info().Msg("database schema initialized")

	return &PgPersistence{
		db: db,
	}, nil
}

func (p *PgPersistence) SaveMembership(ctx context.Context, m *domain.Membership) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO vault.memberships (user_id, vault_id, wrapped_vault_key, nonce, role)
		VALUES ($1, $2, $3, $4, $5)`,
		m.UserID, m.VaultID, m.WrappedVaultKey, m.Nonce, m.Role)
	if err != nil {
		return fmt.Errorf("save membership: %w", err)
	}
	return nil
}

func (p *PgPersistence) GetMembership(ctx context.Context, userID, vaultID uuid.UUID) (*domain.Membership, error) {
	var row struct {
		UserID          uuid.UUID `db:"user_id"`
		VaultID         uuid.UUID `db:"vault_id"`
		WrappedVaultKey []byte    `db:"wrapped_vault_key"`
		Nonce           []byte    `db:"nonce"`
		Role            string    `db:"role"`
		UpdatedAt       any       `db:"updated_at"`
	}
	err := p.db.GetContext(ctx, &row, `
		SELECT user_id, vault_id, wrapped_vault_key, nonce, role, updated_at
		FROM vault.memberships WHERE user_id = $1 AND vault_id = $2`, userID, vaultID)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	return &domain.Membership{
		UserID:          row.UserID,
		VaultID:         row.VaultID,
		WrappedVaultKey: row.WrappedVaultKey,
		Nonce:           row.Nonce,
		Role:            domain.VaultRole(row.Role),
	}, nil
}

func (p *PgPersistence) ListVaultIDsByUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	var rows []struct {
		VaultID uuid.UUID `db:"vault_id"`
	}
	err := p.db.SelectContext(ctx, &rows, `
		SELECT vault_id FROM vault.memberships WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("list vault ids: %w", err)
	}

	var ids []uuid.UUID
	for _, r := range rows {
		ids = append(ids, r.VaultID)
	}
	return ids, nil
}

func (p *PgPersistence) DeleteMembership(ctx context.Context, userID, vaultID uuid.UUID) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM vault.memberships WHERE user_id = $1 AND vault_id = $2`,
		userID, vaultID)
	if err != nil {
		return fmt.Errorf("delete membership: %w", err)
	}
	return nil
}

func (p *PgPersistence) SaveSecret(ctx context.Context, s *domain.SecretValue) error {
	var existing SecretValue
	err := p.db.GetContext(ctx, &existing, `SELECT id FROM vault.secret_values WHERE vault_id = $1 AND id = $2`, s.VaultID, s.ID)

	if err == nil {
		_, err = p.db.ExecContext(ctx, `
			UPDATE vault.secret_values 
			SET ciphertext = $1, wrapped_dek = $2, nonce = $3, version = version + 1, updated_at = NOW()
			WHERE vault_id = $4 AND id = $5`,
			s.Ciphertext, s.WrappedDEK, s.Nonce, s.VaultID, s.ID)
		if err != nil {
			return fmt.Errorf("update secret: %w", err)
		}
		return nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check existing: %w", err)
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO vault.secret_values (id, vault_id, creator_user_id, ciphertext, wrapped_dek, nonce, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		s.ID, s.VaultID, s.CreatorUserID, s.Ciphertext, s.WrappedDEK, s.Nonce, s.Version)
	if err != nil {
		return fmt.Errorf("insert secret: %w", err)
	}

	return nil
}

func (p *PgPersistence) GetSecretValue(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretValue, error) {
	var s SecretValue
	err := p.db.GetContext(ctx, &s, `
		SELECT id, vault_id, creator_user_id, ciphertext, wrapped_dek, nonce, version, updated_at
		FROM vault.secret_values WHERE id = $1 AND version = $2`, secretID, version)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	return &domain.SecretValue{
		ID:            s.ID,
		VaultID:       s.VaultID,
		CreatorUserID: s.CreatorUserID,
		Ciphertext:    s.Ciphertext,
		WrappedDEK:    s.WrappedDEK,
		Nonce:         s.Nonce,
		Version:       s.Version,
		UpdatedAt:     s.UpdatedAt,
	}, nil
}

func (p *PgPersistence) GetSecret(ctx context.Context, secretID uuid.UUID, version *int) (*domain.SecretValue, error) {
	if version == nil {
		v, err := p.GetLatestSecretVersion(ctx, secretID)
		if err != nil {
			return nil, err
		}
		version = &v
	}
	return p.GetSecretValue(ctx, secretID, *version)
}

func (p *PgPersistence) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID) (int, error) {
	var version int
	err := p.db.GetContext(ctx, &version, `
		SELECT COALESCE(MAX(version), 0) FROM vault.secret_values WHERE id = $1`, secretID)
	if err != nil {
		return 0, domain.ErrNotFound
	}
	return version, nil
}

func (p *PgPersistence) DeleteSecret(ctx context.Context, secretID uuid.UUID) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM vault.secret_values WHERE id = $1`, secretID)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

func (p *PgPersistence) GetUserSecretCapabilities(ctx context.Context, userID, secretID uuid.UUID) (*domain.UserSecretCapabilities, error) {
	var row struct {
		UserID       uuid.UUID `db:"user_id"`
		SecretID     uuid.UUID `db:"secret_id"`
		Capabilities []byte    `db:"capabilities"`
		UpdatedAt    time.Time `db:"updated_at"`
	}
	err := p.db.GetContext(ctx, &row, `
		SELECT user_id, secret_id, capabilities, updated_at
		FROM vault.user_secret_capabilities
		WHERE user_id = $1 AND secret_id = $2`, userID, secretID)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	var capList []string
	if err := json.Unmarshal(row.Capabilities, &capList); err != nil {
		return nil, fmt.Errorf("unmarshal capabilities: %w", err)
	}
	return &domain.UserSecretCapabilities{
		UserID:       row.UserID,
		SecretID:     row.SecretID,
		Capabilities: domain.CapabilitiesFromStrings(capList),
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

func (p *PgPersistence) SaveUserSecretCapabilities(ctx context.Context, caps *domain.UserSecretCapabilities) error {
	capsJSON, err := json.Marshal(caps.Capabilities)
	if err != nil {
		return fmt.Errorf("marshal capabilities: %w", err)
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO vault.user_secret_capabilities (user_id, secret_id, capabilities)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, secret_id) DO UPDATE SET capabilities = $3, updated_at = NOW()`,
		caps.UserID, caps.SecretID, capsJSON)
	if err != nil {
		return fmt.Errorf("save user secret capabilities: %w", err)
	}

	return nil
}

func (p *PgPersistence) SaveCheckout(ctx context.Context, checkout *domain.SecretCheckout) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO vault.secret_checkouts (secret_id, version, user_id, checked_out_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (secret_id, version) DO UPDATE SET user_id = $3, checked_out_at = $4`,
		checkout.SecretID, checkout.Version, checkout.UserID, checkout.CheckedOutAt)
	if err != nil {
		return fmt.Errorf("save checkout: %w", err)
	}
	return nil
}

func (p *PgPersistence) GetCheckout(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretCheckout, error) {
	var row struct {
		SecretID     uuid.UUID `db:"secret_id"`
		Version      int       `db:"version"`
		UserID       uuid.UUID `db:"user_id"`
		CheckedOutAt time.Time `db:"checked_out_at"`
	}
	err := p.db.GetContext(ctx, &row, `
		SELECT secret_id, version, user_id, checked_out_at
		FROM vault.secret_checkouts WHERE secret_id = $1 AND version = $2`,
		secretID, version)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	return &domain.SecretCheckout{
		SecretID:     row.SecretID,
		Version:      row.Version,
		UserID:       row.UserID,
		CheckedOutAt: row.CheckedOutAt,
	}, nil
}

func (p *PgPersistence) DeleteCheckout(ctx context.Context, secretID uuid.UUID, version int) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM vault.secret_checkouts WHERE secret_id = $1 AND version = $2`,
		secretID, version)
	if err != nil {
		return fmt.Errorf("delete checkout: %w", err)
	}
	return nil
}

func (p *PgPersistence) SaveMasterWrap(ctx context.Context, mw *domain.MasterWrap) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO vault.master_wraps (vault_id, master_wrapped_key, nonce)
		VALUES ($1, $2, $3)
		ON CONFLICT (vault_id) DO UPDATE SET master_wrapped_key = $2, nonce = $3, updated_at = NOW()`,
		mw.VaultID, mw.MasterWrappedKey, mw.Nonce)
	if err != nil {
		return fmt.Errorf("save master wrap: %w", err)
	}
	return nil
}

func (p *PgPersistence) GetMasterWrap(ctx context.Context, vaultID uuid.UUID) (*domain.MasterWrap, error) {
	var m MasterWrap
	err := p.db.GetContext(ctx, &m, `
		SELECT vault_id, master_wrapped_key, nonce, updated_at
		FROM vault.master_wraps WHERE vault_id = $1`, vaultID)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	return &domain.MasterWrap{
		VaultID:          m.VaultID,
		MasterWrappedKey: m.MasterWrappedKey,
		Nonce:            m.Nonce,
		UpdatedAt:        m.UpdatedAt,
	}, nil
}

func (p *PgPersistence) AppendAuditLog(ctx context.Context, entry *domain.AuditEntry) error {
	prevHMAC := entry.PrevHMAC
	if prevHMAC == nil {
		prevHMAC = []byte{}
	}

	payload, err := json.Marshal(entry.Payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO vault.audit_chain (source_service, correlation_id, event_type, actor_id, action_status, payload, prev_hmac, curr_hmac)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		entry.SourceService, entry.CorrelationID, entry.EventType, entry.ActorID, entry.ActionStatus, payload, prevHMAC, entry.CurrHMAC)
	if err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}

func (p *PgPersistence) GetLastAuditEntry(ctx context.Context) (*domain.AuditEntry, error) {
	var e AuditEntry
	err := p.db.GetContext(ctx, &e, `
		SELECT id, source_service, correlation_id, event_type, actor_id, action_status, payload, prev_hmac, curr_hmac, updated_at
		FROM vault.audit_chain ORDER BY id DESC LIMIT 1`)
	if err != nil {
		return nil, domain.ErrNotFound
	}

	var payload map[string]any
	_ = json.Unmarshal(e.Payload, &payload)

	return &domain.AuditEntry{
		ID:            e.ID,
		SourceService: e.SourceService,
		CorrelationID: e.CorrelationID,
		EventType:     domain.EventType(e.EventType),
		ActorID:       e.ActorID,
		ActionStatus:  e.ActionStatus,
		Payload:       payload,
		PrevHMAC:      e.PrevHMAC,
		CurrHMAC:      e.CurrHMAC,
		UpdatedAt:     e.UpdatedAt,
	}, nil
}
