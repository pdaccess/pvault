package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/rs/zerolog/log"
)

func (s *Impl) Authorize(ctx context.Context, provider domain.IdentityProvider, username, password, externalID string, transitPubKey []byte) (string, string, error) {
	var identity *domain.Identity
	var err error

	if provider == domain.ProviderLocal {
		identity, err = s.AuthenticateLocal(ctx, username, password)
	} else {
		identity, err = s.AuthenticateExternal(ctx, provider, externalID)
	}

	if err != nil {
		s.RecordAudit(ctx, &domain.AuditEntry{
			SourceService: "pvault",
			CorrelationID: uuid.Nil,
			EventType:     domain.EventTypeAuthorize,
			ActorID:       uuid.Nil,
			ActionStatus:  "failure",
			Payload: domain.AuditPayload{
				"provider":    string(provider),
				"username":    username,
				"external_id": externalID,
				"error":       err.Error(),
			},
		})
		return "", "", err
	}

	ku, err := s.getUserRootKey(ctx, identity.InternalID)
	if err != nil {
		return "", "", err
	}

	wrappedKU, err := s.crypto.WrapForTransit(ku, transitPubKey)
	if err != nil {
		return "", "", fmt.Errorf("wrap ku: %w", err)
	}

	s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: identity.InternalID,
		EventType:     domain.EventTypeAuthorize,
		ActorID:       identity.InternalID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"provider": string(provider),
		},
	})

	return identity.InternalID.String(), wrappedKU, nil
}

func (s *Impl) CreateUser(ctx context.Context, username, password, externalID string, provider domain.IdentityProvider, transitPubKey []byte) (string, string, error) {
	if provider == domain.ProviderLocal {
		identity, err := s.repo.GetIdentity(ctx, ports.WithUsername(username))
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("selecting user %s: %w", username, err)
		}

		if identity != nil && err == nil {
			s.RecordAudit(ctx, &domain.AuditEntry{
				SourceService: "pvault",
				CorrelationID: uuid.Nil,
				EventType:     domain.EventTypeCreateUser,
				ActorID:       uuid.Nil,
				ActionStatus:  "failure",
				Payload: domain.AuditPayload{
					"provider": string(provider),
					"username": username,
					"error":    "user already exists",
				},
			})
			return "", "", fmt.Errorf("user already exists %s", username)
		}
	}

	ku := make([]byte, 32)
	if _, err := rand.Read(ku); err != nil {
		return "", "", fmt.Errorf("generate ku: %w", err)
	}

	ks := s.crypto.GetServiceMasterKey()
	wrappedKU, kuNonce, err := s.crypto.Encrypt(ku, ks)
	if err != nil {
		return "", "", fmt.Errorf("wrap ku: %w", err)
	}

	externalIDValue := externalID
	if externalIDValue == "" {
		externalIDValue = username
	}

	internalID := uuid.New()
	passwordHash, err := s.hasher.Hash(password)
	if err != nil {
		return "", "", fmt.Errorf("hashing password: %w", err)
	}

	identity := &domain.Identity{
		InternalID: internalID,
		Provider:   provider,
		ExternalID: &externalID,
		WrappedKU:  wrappedKU,
		KUNonce:    kuNonce,
		IsActive:   true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if username != "" {
		identity.LocalUsername = &username
	}

	if password != "" {
		identity.PasswordHash = &passwordHash
	}

	log.Info().Str("provider", string(provider)).Str("external_id", externalID).Msg("registering identity")

	if err := s.repo.SaveIdentity(ctx, identity); err != nil {
		return "", "", fmt.Errorf("save identity: %w", err)
	}

	wrappedForTransit, err := s.crypto.WrapForTransit(ku, transitPubKey)
	if err != nil {
		return "", "", fmt.Errorf("wrap ku for transit: %w", err)
	}

	s.RecordAudit(ctx, &domain.AuditEntry{
		SourceService: "pvault",
		CorrelationID: internalID,
		EventType:     domain.EventTypeCreateUser,
		ActorID:       internalID,
		ActionStatus:  "success",
		Payload: domain.AuditPayload{
			"provider":    string(provider),
			"username":    username,
			"external_id": externalID,
		},
	})

	return internalID.String(), wrappedForTransit, nil
}

func (s *Impl) getUserRootKey(ctx context.Context, identityID uuid.UUID) ([]byte, error) {
	identity, err := s.repo.GetIdentity(ctx, ports.WithIdentityID(identityID))
	if err != nil {
		return nil, err
	}

	if !identity.IsActive {
		return nil, errors.New("identity is not active")
	}

	ks := s.crypto.GetServiceMasterKey()
	return s.crypto.Decrypt(identity.WrappedKU, ks, identity.KUNonce)
}

func (s *Impl) AuthenticateLocal(ctx context.Context, username, password string) (*domain.Identity, error) {

	// 1. Fetch from DB
	identity, err := s.repo.GetIdentity(ctx, ports.WithUsername(username))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err // Repo handles "not found"
	}

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("no user found:%s", username)
	}

	if identity.PasswordHash == nil {
		return nil, errors.New("no password was set")
	}

	if !identity.IsActive {
		return nil, errors.New("identity_disabled")
	}

	// 2. Perform Argon2id Comparison
	// s.hasher is the Argon2Hasher defined above
	match, err := s.hasher.Compare(password, *identity.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("crypto_failure: %w", err)
	}

	if !match {
		return nil, errors.New("invalid_credentials")
	}

	// 3. Optional: Re-hash if parameters changed
	// If your security policy increases memory requirements, you can
	// check the 'm=' part of the hash here and update it in the DB.

	return identity, nil
}

func (s *Impl) AuthenticateExternal(ctx context.Context, provider domain.IdentityProvider, externalID string) (*domain.Identity, error) {
	identity, err := s.repo.GetIdentity(ctx, ports.WithProvider(provider), ports.WithExternalID(externalID))
	if err != nil {
		return nil, fmt.Errorf("get identity: %w", err)
	}

	if !identity.IsActive {
		return nil, errors.New("identity is not active")
	}

	return identity, nil
}

func (s *Impl) ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error {
	identity, err := s.repo.GetIdentity(ctx, ports.WithProvider(domain.ProviderLocal), ports.WithUsername(username))
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if !identity.IsActive {
		return errors.New("user is not active")
	}

	if identity.PasswordHash == nil {
		return errors.New("user has no password set")
	}

	if ok, err := s.hasher.Compare(oldPassword, *identity.PasswordHash); err != nil || !ok {
		return errors.New("invalid old password")
	}

	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	identity.PasswordHash = &newHash
	identity.UpdatedAt = time.Now()

	return s.repo.SaveIdentity(ctx, identity)
}

func (s *Impl) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	identity, err := s.repo.GetIdentity(ctx, ports.WithIdentityID(userID))
	if err != nil {
		return err
	}

	identity.IsActive = false
	identity.UpdatedAt = time.Now()

	return s.repo.SaveIdentity(ctx, identity)
}
