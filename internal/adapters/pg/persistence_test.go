package pg

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
)

func TestSecret(t *testing.T) {
	t.Parallel()
	backend, err := New(connectionStr)

	if err != nil {
		t.Fatalf("backend shouldn't return error :%v", err)
	}

	buf := make([]byte, 128)
	_, err = rand.Read(buf)
	if err != nil {
		t.Fatalf("random shouldn't return error :%v", err)
	}

	secretID := uuid.New()
	vaultID := uuid.New()

	err = backend.SaveSecret(context.TODO(), &domain.SecretValue{
		ID:         secretID,
		VaultID:    vaultID,
		Ciphertext: buf,
		WrappedDEK: []byte{},
		Nonce:      []byte{},
		Version:    1,
	})

	if err != nil {
		t.Fatalf("SaveSecret shouldn't return error :%v", err)
	}

	secret, err := backend.GetSecret(context.TODO(), secretID, nil)

	if err != nil {
		t.Fatalf("GetSecretValue shouldn't return error :%v", err)
	}

	if string(buf) != string(secret.Ciphertext) {
		t.Fatalf("Write and Read data are different")
	}
}

func TestAudit(t *testing.T) {
	t.Parallel()
	backend, err := New(connectionStr)

	if err != nil {
		t.Errorf("backend shouldn't return error :%v", err)
	}

	correlationID := uuid.New()

	err = backend.AppendAuditLog(context.TODO(), &domain.AuditEntry{
		SourceService: "test",
		CorrelationID: correlationID,
		EventType:     "test_event",
		ActionStatus:  "success",
		Payload:       map[string]any{"key": "value"},
		CurrHMAC:      []byte{},
	})

	if err != nil {
		t.Fatalf("AppendAuditLog shouldn't return error :%v", err)
	}

	entry, err := backend.GetLastAuditEntry(context.TODO())

	if err != nil {
		t.Fatalf("GetLastAuditEntry shouldn't return error :%v", err)
	}

	if entry == nil {
		t.Fatalf("expected at least one entry")
	}
}
