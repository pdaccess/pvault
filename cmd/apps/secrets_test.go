package apps_test

import (
	"context"
	"testing"

	"github.com/pdaccess/pvault/internal/core/domain"
	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

const secretAdminUserID = "990e8400-0000-0000-0000-000000000099"

func TestSecretProtect(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000001"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)
	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  "550e8400-e29b-41d4-a716-446655440001",
		VaultId:   vaultID,
		Plaintext: "my-secret-password-123",
	})
	if err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
	if resp.SecretId == "" {
		t.Error("expected non-empty secret ID")
	}

	assertLastAuditEntry(t, domain.EventTypeProtectSecret, "success")
}

func TestSecretProtectEmptyPlaintext(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000002"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)
	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  "550e8400-e29b-41d4-a716-446655440002",
		VaultId:   vaultID,
		Plaintext: "",
	})
	if err == nil && resp != nil && resp.Success {
		assertLastAuditEntry(t, domain.EventTypeProtectSecret, "success")
	}
}

func TestSecretProtectLongPlaintext(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000003"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)
	longPlaintext := ""
	for i := 0; i < 1000; i++ {
		longPlaintext += "a"
	}

	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  "550e8400-e29b-41d4-a716-446655440003",
		VaultId:   vaultID,
		Plaintext: longPlaintext,
	})
	if err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success for long plaintext")
	}
}

func TestSecretProtectDuplicate(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000005"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)
	secretID := "550e8400-e29b-41d4-a716-446655440004"

	_, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  secretID,
		VaultId:   vaultID,
		Plaintext: "first-value",
	})
	if err != nil {
		t.Logf("first ProtectSecret: %v", err)
	}

	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  secretID,
		VaultId:   vaultID,
		Plaintext: "second-value",
	})
	if err != nil {
		t.Logf("second ProtectSecret: %v", err)
	}
	if resp != nil && resp.Success {
		t.Log("duplicate secret was overwritten")
	}
}

func TestSecretProtectInvalidSecretID(t *testing.T) {
	ctx := withAuth(context.Background(), secretAdminUserID)

	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  "not-a-uuid",
		VaultId:   "990e8400-0000-0000-0000-000000000001",
		Plaintext: "some secret",
	})
	if err == nil {
		t.Error("expected error for invalid secret ID")
	}
	if resp != nil && resp.Success {
		t.Error("expected failure for invalid secret ID")
	}
}

func TestSecretUncover(t *testing.T) {
	const (
		vaultID  = "990e8400-0000-0000-0000-000000000104"
		secretID = "550e8400-e29b-41d4-a716-446655440010"
		want     = "round-trip-secret-value"
	)
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)

	protResp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  secretID,
		VaultId:   vaultID,
		Plaintext: want,
	})
	if err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}
	if !protResp.Success {
		t.Fatal("expected protect success")
	}

	uncResp, err := client.UncoverSecret(ctx, &pgrpc.UncoverSecretRequest{
		SecretId: secretID,
		VaultId:  vaultID,
		Action:   "see",
	})
	if err != nil {
		t.Fatalf("UncoverSecret failed: %v", err)
	}
	if uncResp.Plaintext != want {
		t.Errorf("plaintext: want %q, got %q", want, uncResp.Plaintext)
	}

	assertLastAuditEntry(t, domain.EventTypeUncoverSecret, "success")
}

func TestSecretUncoverWithoutPermission(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000006"
	mustCreateVault(t, vaultID, secretAdminUserID)

	const outsiderID = "990e8400-ffff-0000-0000-000000000001"
	ctx := withAuth(context.Background(), outsiderID)

	resp, err := client.UncoverSecret(ctx, &pgrpc.UncoverSecretRequest{
		SecretId: "550e8400-e29b-41d4-a716-446655440011",
		VaultId:  vaultID,
		Action:   "see",
	})
	if err == nil {
		t.Error("expected unauthorized error for user with no membership")
	}
	if resp != nil && resp.Plaintext != "" {
		t.Error("expected empty plaintext for unauthorized user")
	}
}

func TestSecretUncoverInvalidSecretID(t *testing.T) {
	ctx := withAuth(context.Background(), secretAdminUserID)

	resp, err := client.UncoverSecret(ctx, &pgrpc.UncoverSecretRequest{
		SecretId: "invalid-secret-id",
		VaultId:  "990e8400-0000-0000-0000-000000000001",
		Action:   "see",
	})
	if err == nil {
		t.Error("expected error for invalid secret ID")
	}
	if resp != nil && resp.Plaintext != "" {
		t.Error("expected empty plaintext for invalid secret ID")
	}
}

func TestSecretUncoverInvalidVaultID(t *testing.T) {
	ctx := withAuth(context.Background(), secretAdminUserID)

	resp, err := client.UncoverSecret(ctx, &pgrpc.UncoverSecretRequest{
		SecretId: "550e8400-e29b-41d4-a716-446655440012",
		VaultId:  "invalid-vault-id",
		Action:   "see",
	})
	if err == nil {
		t.Error("expected error for invalid vault ID")
	}
	if resp != nil && resp.Plaintext != "" {
		t.Error("expected empty plaintext for invalid vault ID")
	}
}

func TestSecretUncoverDifferentActions(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000007"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)
	actions := []string{"read", "write", "delete", "connect", "admin"}

	for _, action := range actions {
		_, err := client.UncoverSecret(ctx, &pgrpc.UncoverSecretRequest{
			SecretId: "550e8400-e29b-41d4-a716-446655440013",
			VaultId:  vaultID,
			Action:   action,
		})
		_ = err
	}
}

func TestSecretProtectSpecialCharacters(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000207"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)

	testCases := []struct {
		name      string
		secretID  string
		plaintext string
	}{
		{"unicode", "550e8400-e29b-41d4-a716-446655440021", "密码123"},
		{"emoji", "550e8400-e29b-41d4-a716-446655440022", "🔐 password 🎉"},
		{"newlines", "550e8400-e29b-41d4-a716-446655440023", "line1\nline2\nline3"},
		{"tabs", "550e8400-e29b-41d4-a716-446655440024", "col1\tcol2\tcol3"},
		{"quotes", "550e8400-e29b-41d4-a716-446655440025", `{"key": "value"}`},
		{"backticks", "550e8400-e29b-41d4-a716-446655440026", "`code`"},
		{"mixed", "550e8400-e29b-41d4-a716-446655440027", "Passw0rd!@#$%^&*()"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
				SecretId:  tc.secretID,
				VaultId:   vaultID,
				Plaintext: tc.plaintext,
			})
			if err != nil {
				t.Errorf("ProtectSecret(%s) failed: %v", tc.name, err)
				return
			}
			if !resp.Success {
				t.Errorf("ProtectSecret(%s): expected success", tc.name)
				return
			}

			assertLastAuditEntry(t, domain.EventTypeProtectSecret, "success")
		})
	}
}

func TestSecretCapabilitiesDefault(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000008"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)

	_, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:     "550e8400-e29b-41d4-a716-446655440030",
		VaultId:      vaultID,
		Plaintext:    "secret with default capabilities",
		Capabilities: []string{},
	})
	if err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}

	assertLastAuditEntry(t, domain.EventTypeProtectSecret, "success")
}

func TestSecretCapabilitiesExplicit(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000009"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)

	_, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:     "550e8400-e29b-41d4-a716-446655440031",
		VaultId:      vaultID,
		Plaintext:    "secret with explicit capabilities",
		Capabilities: []string{"see", "write"},
	})
	if err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}

	assertLastAuditEntry(t, domain.EventTypeProtectSecret, "success")
}

func TestSecretUncoverWithoutCapability(t *testing.T) {
	const (
		vaultID   = "990e8400-0000-0000-0000-000000000010"
		secretID  = "550e8400-e29b-41d4-a716-446655440032"
		newUserID = "990e8400-ffff-0000-0000-000000000010"
	)
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctxAdmin := withAuth(context.Background(), secretAdminUserID)

	_, err := client.ProtectSecret(ctxAdmin, &pgrpc.ProtectSecretRequest{
		SecretId:  secretID,
		VaultId:   vaultID,
		Plaintext: "secret without user capabilities",
	})
	if err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}

	_, err = client.CreateMembership(ctxAdmin, &pgrpc.CreateMembershipRequest{
		UserId:  newUserID,
		VaultId: vaultID,
		Role:    "user",
	})
	if err != nil {
		t.Fatalf("CreateMembership failed: %v", err)
	}

	ctxNewUser := withAuth(context.Background(), newUserID)
	_, err = client.UncoverSecret(ctxNewUser, &pgrpc.UncoverSecretRequest{
		SecretId: secretID,
		VaultId:  vaultID,
		Action:   "see",
	})
	if err == nil {
		t.Error("expected error when user has no capabilities on secret")
	}
}

func TestSecretUncoverWithCapability(t *testing.T) {
	t.Skip("UpdateSecretCapabilities RPC not yet implemented in proto")
}

func TestAdminUpdateSecretCapabilities(t *testing.T) {
	const (
		vaultID  = "990e8400-0000-0000-0000-000000000012"
		secretID = "550e8400-e29b-41d4-a716-446655440034"
		memberID = "990e8400-ffff-0000-0000-000000000012"
	)
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctxAdmin := withAuth(context.Background(), secretAdminUserID)

	_, err := client.ProtectSecret(ctxAdmin, &pgrpc.ProtectSecretRequest{
		SecretId:  secretID,
		VaultId:   vaultID,
		Plaintext: "secret for admin capability test",
	})
	if err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}

	_, err = client.CreateMembership(ctxAdmin, &pgrpc.CreateMembershipRequest{
		UserId:  memberID,
		VaultId: vaultID,
		Role:    "operator",
	})
	if err != nil {
		t.Fatalf("CreateMembership failed: %v", err)
	}

	resp, err := client.ProtectSecret(ctxAdmin, &pgrpc.ProtectSecretRequest{
		SecretId:     secretID,
		VaultId:      vaultID,
		Plaintext:    "updated secret",
		Capabilities: []string{"see", "connect", "write"},
	})
	if err != nil {
		t.Fatalf("ProtectSecret by admin failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
}

func TestOperatorCannotUpdateCapabilities(t *testing.T) {
	t.Skip("UpdateSecretCapabilities RPC not yet implemented in proto")
}
