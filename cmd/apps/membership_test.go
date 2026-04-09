package apps_test

import (
	"context"
	"testing"

	"github.com/pdaccess/pvault/internal/core/domain"
	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

var testUserRootKey = []byte("testtesttesttesttesttesttesttest")

const testAdminUserID = "880e8400-0000-0000-0000-000000000099"

func mustCreateVault(t *testing.T, vaultID, adminUserID string) {
	t.Helper()
	ctx := withAuth(context.Background(), adminUserID)
	resp, err := client.CreateVault(ctx, &pgrpc.CreateVaultRequest{
		VaultId: vaultID,
	})
	if err != nil {
		t.Fatalf("mustCreateVault: %v", err)
	}
	if !resp.Success {
		t.Fatalf("mustCreateVault: %s", resp.Message)
	}
}

func assertLastAuditEntry(t *testing.T, wantEventType domain.EventType, wantStatus string) {
	t.Helper()
	entry, err := pg.GetLastAuditEntry(context.Background())
	if err != nil {
		t.Fatalf("GetLastAuditEntry: %v", err)
	}
	if entry == nil {
		t.Fatal("expected audit entry in database, got nil")
	}
	if entry.EventType != wantEventType {
		t.Errorf("audit event_type: want %q, got %q", wantEventType, entry.EventType)
	}
	if entry.ActionStatus != wantStatus {
		t.Errorf("audit action_status: want %q, got %q", wantStatus, entry.ActionStatus)
	}
	if len(entry.CurrHMAC) == 0 {
		t.Error("audit curr_hmac must not be empty")
	}
}

func TestMembershipCreate(t *testing.T) {
	const vaultID = "880e8400-0000-0000-0000-000000000001"
	mustCreateVault(t, vaultID, testAdminUserID)

	ctx := withAuth(context.Background(), testAdminUserID)
	resp, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:  "550e8400-e29b-41d4-a716-446655440000",
		VaultId: vaultID,
		Role:    "operator",
	})
	if err != nil {
		t.Fatalf("CreateMembership failed: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success, got: %s", resp.Message)
	}

	assertLastAuditEntry(t, domain.EventTypeAddMember, "success")
}

func TestMembershipCreateInvalidUserID(t *testing.T) {
	ctx := withAuth(context.Background(), testAdminUserID)

	resp, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:  "invalid-uuid",
		VaultId: "550e8400-e29b-41d4-a716-446655440001",
		Role:    "user",
	})
	if err == nil {
		t.Error("expected error for invalid user ID")
	}
	if resp != nil && resp.Success {
		t.Error("expected failure for invalid user ID")
	}
}

func TestMembershipCreateInvalidVaultID(t *testing.T) {
	ctx := withAuth(context.Background(), testAdminUserID)

	resp, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:  "550e8400-e29b-41d4-a716-446655440000",
		VaultId: "invalid-vault",
		Role:    "user",
	})
	if err == nil {
		t.Error("expected error for invalid vault ID")
	}
	if resp != nil && resp.Success {
		t.Error("expected failure for invalid vault ID")
	}
}

func TestMembershipCreateEmptyRole(t *testing.T) {
	const vaultID = "880e8400-0000-0000-0000-000000000002"
	mustCreateVault(t, vaultID, testAdminUserID)

	ctx := withAuth(context.Background(), testAdminUserID)
	resp, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:  "550e8400-e29b-41d4-a716-446655440002",
		VaultId: vaultID,
		Role:    "",
	})
	if err == nil && resp != nil && resp.Success {
		assertLastAuditEntry(t, domain.EventTypeAddMember, "success")
	}
}

func TestMembershipCreateDuplicate(t *testing.T) {
	const (
		vaultID  = "880e8400-0000-0000-0000-000000000004"
		memberID = "550e8400-e29b-41d4-a716-446655440010"
	)
	mustCreateVault(t, vaultID, testAdminUserID)

	ctx := withAuth(context.Background(), testAdminUserID)
	req := &pgrpc.CreateMembershipRequest{
		UserId:  memberID,
		VaultId: vaultID,
		Role:    "admin",
	}

	if _, err := client.CreateMembership(ctx, req); err != nil {
		t.Logf("first create: %v", err)
	} else {
		assertLastAuditEntry(t, domain.EventTypeAddMember, "success")
	}

	_, _ = client.CreateMembership(ctx, req)
}

func TestListAuthorizedVaults(t *testing.T) {
	const vaultID = "880e8400-0000-0000-0000-000000000005"
	mustCreateVault(t, vaultID, testAdminUserID)

	ctx := withAuth(context.Background(), testAdminUserID)

	_, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:  "550e8400-e29b-41d4-a716-446655440020",
		VaultId: vaultID,
		Role:    "operator",
	})
	if err != nil {
		t.Logf("create membership: %v", err)
	} else {
		assertLastAuditEntry(t, domain.EventTypeAddMember, "success")
	}

	resp, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	if err != nil {
		t.Fatalf("ListAuthorizedVaults failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.VaultIds) == 0 {
		t.Error("expected at least one vault")
	}
	t.Logf("vault IDs: %v", resp.VaultIds)
}

func TestListAuthorizedVaultsNoMembership(t *testing.T) {
	const noMemberUserID = "110e8400-0000-0000-0000-000000000000"
	ctx := withAuth(context.Background(), noMemberUserID)

	resp, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	if err != nil {
		t.Fatalf("ListAuthorizedVaults failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.VaultIds) != 0 {
		t.Errorf("expected empty vault ids, got: %v", resp.VaultIds)
	}
}
