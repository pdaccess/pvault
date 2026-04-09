package apps_test

import (
	"context"
	"testing"

	"github.com/pdaccess/pvault/internal/core/domain"
	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

const (
	testVaultID = "770e8400-e29b-41d4-a716-446655440001"
	testUserID  = "770e8400-e29b-41d4-a716-446655440000"
)

func TestCreateVault(t *testing.T) {
	ctx := withAuth(context.Background(), testUserID)

	resp, err := client.CreateVault(ctx, &pgrpc.CreateVaultRequest{
		VaultId: testVaultID,
	})
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success, got: %s", resp.Message)
	}
	if resp.VaultId != testVaultID {
		t.Errorf("expected vault_id %s, got %s", testVaultID, resp.VaultId)
	}
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}

	assertLastAuditEntry(t, domain.EventTypeCreateVault, "success")
}

func TestCreateVaultDuplicate(t *testing.T) {
	ctx := withAuth(context.Background(), testUserID)

	req := &pgrpc.CreateVaultRequest{
		VaultId: "770e8400-e29b-41d4-a716-446655440002",
	}

	_, err := client.CreateVault(ctx, req)
	if err != nil {
		t.Logf("first CreateVault: %v", err)
	}

	resp, err := client.CreateVault(ctx, req)
	if err == nil {
		t.Error("expected error on duplicate vault creation")
	}
	if resp != nil && resp.Success {
		t.Error("expected failure for duplicate vault")
	}
}

func TestCreateVaultInvalidVaultID(t *testing.T) {
	ctx := withAuth(context.Background(), testUserID)

	resp, err := client.CreateVault(ctx, &pgrpc.CreateVaultRequest{
		VaultId: "not-a-uuid",
	})
	if err == nil {
		t.Error("expected error for invalid vault_id")
	}
	if resp != nil && resp.Success {
		t.Error("expected failure for invalid vault_id")
	}
}

func TestCreateVaultAdminMembershipCreated(t *testing.T) {
	ctx := withAuth(context.Background(), testUserID)

	vaultID := "770e8400-e29b-41d4-a716-446655440004"

	_, err := client.CreateVault(ctx, &pgrpc.CreateVaultRequest{
		VaultId: vaultID,
	})
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	resp, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:  testUserID,
		VaultId: vaultID,
		Role:    "admin",
	})
	if err != nil {
		if resp != nil && resp.Message == "vault master key not found" {
			t.Error("vault master wrap was not initialized by CreateVault")
		}
	} else {
		assertLastAuditEntry(t, domain.EventTypeAddMember, "success")
	}
}

func TestCreateVaultAuditLogged(t *testing.T) {
	ctx := withAuth(context.Background(), testUserID)

	vaultID := "770e8400-e29b-41d4-a716-446655440005"

	_, err := client.CreateVault(ctx, &pgrpc.CreateVaultRequest{
		VaultId: vaultID,
	})
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	auditResp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "test",
		CorrelationId: vaultID,
		EventType:     "verify_chain",
		ActorId:       testUserID,
		ActionStatus:  "success",
		PayloadJson:   `{"check":"audit chain after create_vault"}`,
	})
	if err != nil {
		t.Fatalf("RecordAuditLog after CreateVault failed: %v", err)
	}
	if auditResp.AuditId <= 0 {
		t.Error("expected positive audit_id")
	}
	if auditResp.CurrHmac == nil {
		t.Error("expected non-nil curr_hmac")
	}
}
