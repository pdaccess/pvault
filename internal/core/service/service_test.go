package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/adapters/mock"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	ctx          context.Context
	serviceImpl  ports.VaultService
	checkoutRepo ports.SecretRepository
)

type testRepo struct {
	ports.SecretRepository
	checkouts   map[uuid.UUID]map[int]*domain.SecretCheckout
	secrets     map[uuid.UUID]map[uuid.UUID]*domain.SecretValue
	memberships map[uuid.UUID]map[uuid.UUID]*domain.Membership
	caps        map[uuid.UUID]map[uuid.UUID]*domain.UserSecretCapabilities
}

func (t *testRepo) SaveSecret(ctx context.Context, s *domain.SecretValue) error {
	if t.secrets == nil {
		t.secrets = make(map[uuid.UUID]map[uuid.UUID]*domain.SecretValue)
	}
	if t.secrets[s.VaultID] == nil {
		t.secrets[s.VaultID] = make(map[uuid.UUID]*domain.SecretValue)
	}
	t.secrets[s.VaultID][s.ID] = s
	return nil
}

func (t *testRepo) GetSecret(ctx context.Context, secretID uuid.UUID, version *int) (*domain.SecretValue, error) {
	if t.secrets == nil {
		return nil, domain.ErrNotFound
	}
	for _, vaultSecrets := range t.secrets {
		if s, ok := vaultSecrets[secretID]; ok {
			if version != nil && s.Version != *version {
				continue
			}
			return s, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (t *testRepo) GetMembership(ctx context.Context, userID, vaultID uuid.UUID) (*domain.Membership, error) {
	if t.memberships == nil {
		return nil, domain.ErrNotFound
	}
	if vaultMem := t.memberships[userID]; vaultMem != nil {
		if mem, ok := vaultMem[vaultID]; ok {
			return mem, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (t *testRepo) SaveMembership(ctx context.Context, m *domain.Membership) error {
	if t.memberships == nil {
		t.memberships = make(map[uuid.UUID]map[uuid.UUID]*domain.Membership)
	}
	if t.memberships[m.UserID] == nil {
		t.memberships[m.UserID] = make(map[uuid.UUID]*domain.Membership)
	}
	t.memberships[m.UserID][m.VaultID] = m
	return nil
}

func (t *testRepo) GetUserSecretCapabilities(ctx context.Context, userID, secretID uuid.UUID) (*domain.UserSecretCapabilities, error) {
	if t.caps == nil {
		return nil, domain.ErrNotFound
	}
	if userCaps := t.caps[userID]; userCaps != nil {
		if caps, ok := userCaps[secretID]; ok {
			return caps, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (t *testRepo) SaveUserSecretCapabilities(ctx context.Context, caps *domain.UserSecretCapabilities) error {
	if t.caps == nil {
		t.caps = make(map[uuid.UUID]map[uuid.UUID]*domain.UserSecretCapabilities)
	}
	if t.caps[caps.UserID] == nil {
		t.caps[caps.UserID] = make(map[uuid.UUID]*domain.UserSecretCapabilities)
	}
	t.caps[caps.UserID][caps.SecretID] = caps
	return nil
}

func (t *testRepo) SaveCheckout(ctx context.Context, checkout *domain.SecretCheckout) error {
	if t.checkouts == nil {
		t.checkouts = make(map[uuid.UUID]map[int]*domain.SecretCheckout)
	}
	if t.checkouts[checkout.SecretID] == nil {
		t.checkouts[checkout.SecretID] = make(map[int]*domain.SecretCheckout)
	}
	t.checkouts[checkout.SecretID][checkout.Version] = checkout
	return nil
}

func (t *testRepo) GetCheckout(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretCheckout, error) {
	if t.checkouts == nil {
		return nil, domain.ErrNotFound
	}
	if versions, ok := t.checkouts[secretID]; ok {
		if checkout, ok := versions[version]; ok {
			return checkout, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (t *testRepo) DeleteCheckout(ctx context.Context, secretID uuid.UUID, version int) error {
	if t.checkouts != nil {
		if versions, ok := t.checkouts[secretID]; ok {
			delete(versions, version)
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	ctx = log.With().
		Str("component", "module").
		Logger().WithContext(context.Background())

	testRepo := &testRepo{
		SecretRepository: mock.New(),
	}
	var err error
	logger := zerolog.New(os.Stdout)
	serviceImpl, err = New(testRepo, mock.NewCryptoService(), logger)
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("service init")
		os.Exit(1)
	}
	checkoutRepo = testRepo

	ctx = context.WithValue(ctx, domain.UserTokenIn, "empty")

	m.Run()
}

func TestCheckInCheckOut(t *testing.T) {
	vaultID := uuid.New()
	adminUserID := uuid.New()
	userAID := uuid.New()
	userBID := uuid.New()
	secretID := uuid.New()

	testRepo := checkoutRepo.(*testRepo)

	if err := serviceImpl.CreateVault(ctx, vaultID, adminUserID, []byte("test-root-key")); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	if err := serviceImpl.CreateMembership(ctx, adminUserID, userAID, vaultID, []byte("wrapped-vault-key"), domain.UserRole); err != nil {
		t.Fatalf("CreateMembership for userA failed: %v", err)
	}

	if err := serviceImpl.CreateMembership(ctx, adminUserID, userBID, vaultID, []byte("wrapped-vault-key"), domain.UserRole); err != nil {
		t.Fatalf("CreateMembership for userB failed: %v", err)
	}

	if err := testRepo.SaveSecret(ctx, &domain.SecretValue{
		ID:            secretID,
		VaultID:       vaultID,
		CreatorUserID: adminUserID,
		Ciphertext:    []byte("super-secret-password"),
		WrappedDEK:    []byte("1234567890123456789012345678901234567890123456789012345678901234"),
		Nonce:         []byte("nonce12345678"),
		Version:       1,
	}); err != nil {
		t.Fatalf("SaveSecret failed: %v", err)
	}

	if err := testRepo.SaveUserSecretCapabilities(ctx, &domain.UserSecretCapabilities{
		UserID:       adminUserID,
		SecretID:     secretID,
		Capabilities: domain.Capabilities{domain.CapSee, domain.CapCheck, domain.CapWrite},
	}); err != nil {
		t.Fatalf("SaveUserSecretCapabilities for admin failed: %v", err)
	}

	if err := testRepo.SaveUserSecretCapabilities(ctx, &domain.UserSecretCapabilities{
		UserID:       userAID,
		SecretID:     secretID,
		Capabilities: domain.Capabilities{domain.CapSee, domain.CapCheck},
	}); err != nil {
		t.Fatalf("SaveUserSecretCapabilities for userA failed: %v", err)
	}

	if err := testRepo.SaveUserSecretCapabilities(ctx, &domain.UserSecretCapabilities{
		UserID:       userBID,
		SecretID:     secretID,
		Capabilities: domain.Capabilities{domain.CapSee},
	}); err != nil {
		t.Fatalf("SaveUserSecretCapabilities for userB failed: %v", err)
	}

	_, version, err := serviceImpl.UncoverSecret(ctx, userAID, secretID, domain.CapCheck, nil)
	if err != nil {
		t.Fatalf("check-in failed: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected version 1, got %d", version)
	}

	plaintext, _, err := serviceImpl.UncoverSecret(ctx, userAID, secretID, domain.CapSee, nil)
	if err != nil {
		t.Fatalf("user A should see secret after check-in: %v", err)
	}
	if plaintext != "super-secret-password" {
		t.Fatalf("expected plaintext, got: %v", plaintext)
	}

	_, _, err = serviceImpl.UncoverSecret(ctx, userBID, secretID, domain.CapSee, nil)
	if err == nil {
		t.Fatal("expected error when accessing checked-out secret, got nil")
	}
	if err.Error() != "secret checked out by another user" {
		t.Fatalf("expected 'secret checked out by another user', got: %v", err)
	}

	_, version, err = serviceImpl.UncoverSecret(ctx, userAID, secretID, domain.CapCheck, nil)
	if err != nil {
		t.Fatalf("check-out failed: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected version 1, got %d", version)
	}

	plaintext, _, err = serviceImpl.UncoverSecret(ctx, userBID, secretID, domain.CapSee, nil)
	if err != nil {
		t.Fatalf("expected to see secret after check-out: %v", err)
	}
	if plaintext != "super-secret-password" {
		t.Fatalf("expected plaintext, got: %v", plaintext)
	}

	_ = testRepo.DeleteCheckout(ctx, secretID, 1)
	expiredCheckout := &domain.SecretCheckout{
		SecretID:     secretID,
		Version:      1,
		UserID:       userAID,
		CheckedOutAt: time.Now().Add(-2 * time.Hour),
	}
	if err := testRepo.SaveCheckout(ctx, expiredCheckout); err != nil {
		t.Fatalf("SaveCheckout failed: %v", err)
	}

	plaintext, _, err = serviceImpl.UncoverSecret(ctx, userBID, secretID, domain.CapSee, nil)
	if err != nil {
		t.Fatalf("expected to see secret after expired checkout: %v", err)
	}
	if plaintext != "super-secret-password" {
		t.Fatalf("expected plaintext after expired, got: %v", plaintext)
	}
}
