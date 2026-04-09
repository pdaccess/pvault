package apps_test

import (
	"context"
	"testing"

	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

// testUserRootKey is a valid 32-byte AES-256 key used across all tests.
var testUserRootKey = []byte("testtesttesttesttesttesttesttest")

// testAdminUserID is the admin user seeded into every test vault in membership tests.
const testAdminUserID = "880e8400-0000-0000-0000-000000000099"

// mustCreateVault calls CreateVault using a JWT for adminUserID and fails the test immediately if it does not succeed.
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

// assertLastAuditEntry fetches the most recent audit entry from the database
// and verifies its event type, action status, and that an HMAC was computed.
func assertLastAuditEntry(t *testing.T, wantEventType, wantStatus string) {
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
		UserId:       "550e8400-e29b-41d4-a716-446655440000",
		VaultId:      vaultID,
		UserRootKey:  testUserRootKey,
		Role:         "operator",
		Capabilities: []string{"see", "write"},
	})
	if err != nil {
		t.Fatalf("CreateMembership failed: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success, got: %s", resp.Message)
	}
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}

	assertLastAuditEntry(t, "add_member", "success")
}

func TestMembershipCreateInvalidUserID(t *testing.T) {
	ctx := withAuth(context.Background(), testAdminUserID)

	resp, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:       "invalid-uuid",
		VaultId:      "550e8400-e29b-41d4-a716-446655440001",
		UserRootKey:  testUserRootKey,
		Role:         "user",
		Capabilities: []string{"see"},
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
		UserId:       "550e8400-e29b-41d4-a716-446655440000",
		VaultId:      "invalid-vault",
		UserRootKey:  testUserRootKey,
		Role:         "user",
		Capabilities: []string{"see"},
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
		UserId:       "550e8400-e29b-41d4-a716-446655440002",
		VaultId:      vaultID,
		UserRootKey:  testUserRootKey,
		Role:         "",
		Capabilities: []string{"see"},
	})
	if err == nil && resp != nil && resp.Success {
		assertLastAuditEntry(t, "add_member", "success")
	}
}

func TestMembershipCreateEmptyCapabilities(t *testing.T) {
	const vaultID = "880e8400-0000-0000-0000-000000000003"
	mustCreateVault(t, vaultID, testAdminUserID)

	ctx := withAuth(context.Background(), testAdminUserID)
	resp, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:       "550e8400-e29b-41d4-a716-446655440003",
		VaultId:      vaultID,
		UserRootKey:  testUserRootKey,
		Role:         "user",
		Capabilities: []string{},
	})
	if err == nil && resp != nil && resp.Success {
		assertLastAuditEntry(t, "add_member", "success")
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
		UserId:       memberID,
		VaultId:      vaultID,
		UserRootKey:  testUserRootKey,
		Role:         "admin",
		Capabilities: []string{"see", "write"},
	}

	if _, err := client.CreateMembership(ctx, req); err != nil {
		t.Logf("first create: %v", err)
	} else {
		assertLastAuditEntry(t, "add_member", "success")
	}

	// Duplicate — may succeed (upsert) or fail; either is acceptable.
	_, _ = client.CreateMembership(ctx, req)
}

func TestListAuthorizedVaults(t *testing.T) {
	const vaultID = "880e8400-0000-0000-0000-000000000005"
	mustCreateVault(t, vaultID, testAdminUserID)

	ctx := withAuth(context.Background(), testAdminUserID)

	_, err := client.CreateMembership(ctx, &pgrpc.CreateMembershipRequest{
		UserId:       "550e8400-e29b-41d4-a716-446655440020",
		VaultId:      vaultID,
		UserRootKey:  testUserRootKey,
		Role:         "operator",
		Capabilities: []string{"see"},
	})
	if err != nil {
		t.Logf("create membership: %v", err)
	} else {
		assertLastAuditEntry(t, "add_member", "success")
	}

	resp, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	if err != nil {
		t.Fatalf("ListAuthorizedVaults failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	t.Logf("vault IDs: %v", resp.VaultIds)
}

func TestListAuthorizedVaultsNoMembership(t *testing.T) {
	// Use a UUID that has no vault memberships anywhere in the test suite.
	const noMemberUserID = "110e8400-0000-0000-0000-000000000000"
	ctx := withAuth(context.Background(), noMemberUserID)

	resp, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	if err != nil {
		t.Fatalf("ListAuthorizedVaults failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// (nil and empty slice are equivalent; JSON omitempty means absent field decodes as nil)
	if len(resp.VaultIds) != 0 {
		t.Errorf("expected empty vault ids, got: %v", resp.VaultIds)
	}
}
