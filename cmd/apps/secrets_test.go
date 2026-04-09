package apps_test

import (
	"context"
	"testing"

	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

// secretAdminUserID is the admin user used when creating vaults for secret tests.
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

	assertLastAuditEntry(t, "protect_secret", "success")
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
		assertLastAuditEntry(t, "protect_secret", "success")
	}
}

func TestSecretProtectLongPlaintext(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000003"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)

	longPlaintext := make([]byte, 10240)
	for i := range longPlaintext {
		longPlaintext[i] = byte(i % 256)
	}

	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  "550e8400-e29b-41d4-a716-446655440003",
		VaultId:   vaultID,
		Plaintext: string(longPlaintext),
	})
	if err != nil {
		t.Fatalf("ProtectSecret with long plaintext failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success for long plaintext")
	}

	assertLastAuditEntry(t, "protect_secret", "success")
}

func TestSecretProtectInvalidVaultID(t *testing.T) {
	ctx := withAuth(context.Background(), secretAdminUserID)

	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  "550e8400-e29b-41d4-a716-446655440004",
		VaultId:   "invalid-vault-id",
		Plaintext: "test-password",
	})
	if err == nil {
		t.Error("expected error for invalid vault ID")
	}
	if resp != nil && resp.Success {
		t.Error("expected failure for invalid vault ID")
	}
}

func TestSecretProtectInvalidSecretID(t *testing.T) {
	ctx := withAuth(context.Background(), secretAdminUserID)

	resp, err := client.ProtectSecret(ctx, &pgrpc.ProtectSecretRequest{
		SecretId:  "invalid-secret-id",
		VaultId:   "990e8400-0000-0000-0000-000000000001",
		Plaintext: "test-password",
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
		vaultID  = "990e8400-0000-0000-0000-000000000004"
		secretID = "550e8400-e29b-41d4-a716-446655440010"
		want     = "round-trip-secret-value"
	)
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)

	// Protect a secret first.
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

	// Now uncover it — the JWT carries the user's root key for decryption.
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

	assertLastAuditEntry(t, "uncover_secret", "success")
}

func TestSecretUncoverWithoutPermission(t *testing.T) {
	const vaultID = "990e8400-0000-0000-0000-000000000005"
	mustCreateVault(t, vaultID, secretAdminUserID)

	// Use a user that has no membership in this vault.
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
	const vaultID = "990e8400-0000-0000-0000-000000000006"
	mustCreateVault(t, vaultID, secretAdminUserID)

	ctx := withAuth(context.Background(), secretAdminUserID)
	// Admin capabilities: see, write, delete, connect — "read" and "admin" are not in the list.
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
	const vaultID = "990e8400-0000-0000-0000-000000000007"
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

			assertLastAuditEntry(t, "protect_secret", "success")
		})
	}
}
