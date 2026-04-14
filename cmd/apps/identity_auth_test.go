package apps_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/pdaccess/pvault/internal/adapters/crypto"
	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

var testCrypto = crypto.NewAESGCMService(make([]byte, 32))

func generateTransitKey(t *testing.T) ([]byte, *ecdh.PrivateKey) {
	t.Helper()
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generateTransitKey: %v", err)
	}
	return privKey.PublicKey().Bytes(), privKey
}

func TestCreateUserLocalProvider(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	username := "localuser" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000001", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	resp, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "password123",
		ExternalId: "",
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if !resp.Success {
		t.Fatal("CreateUser returned success=false")
	}
	if resp.UserId == "" {
		t.Fatal("CreateUser returned empty user_id")
	}
	if resp.WrappedUserRootKey == "" {
		t.Fatal("CreateUser returned nil wrapped_user_root_key")
	}
	t.Logf("Created user: %s", resp.UserId)
}

func TestCreateUserKeycloakProvider(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	externalID := "keycloak-" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000002", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	resp, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   "",
		Password:   "",
		ExternalId: externalID,
		Provider:   "keycloak",
	})
	if err != nil {
		t.Fatalf("CreateUser keycloak failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("CreateUser returned success=false")
	}
	t.Logf("Created keycloak user: %s", resp.UserId)
}

func TestChangePassword(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	username := "cpuser" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000004", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	createResp, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "oldpassword",
		ExternalId: "",
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if !createResp.Success {
		t.Fatal("CreateUser returned success=false")
	}
	t.Logf("Created user for password change: %s", createResp.UserId)

	changeResp, err := client.ChangePassword(ctx, &pgrpc.ChangePasswordRequest{
		Username:    username,
		OldPassword: "oldpassword",
		NewPassword: "newpassword",
	})
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	if !changeResp.Success {
		t.Fatalf("ChangePassword returned success=false: %s", changeResp.Message)
	}
	t.Logf("Password changed successfully for user: %s", username)
}

func TestAuthorizeLocalProvider(t *testing.T) {
	transitKey, transitPrivKey := generateTransitKey(t)
	username := "authuser" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000005", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	createResp, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "testpassword",
		ExternalId: "",
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if !createResp.Success {
		t.Fatal("CreateUser returned success=false")
	}
	t.Logf("Created user: %s", createResp.UserId)

	authToken := makeTestToken("00000000-0000-0000-0000-000000000005", testUserRootKey, transitKey)
	authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authToken))

	authResp, err := client.Authorize(authCtx, &pgrpc.AuthorizeRequest{
		AuthType: &pgrpc.AuthorizeRequest_Local{
			Local: &pgrpc.LocalAuth{
				Username: username,
				Password: "testpassword",
			},
		},
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !authResp.Success {
		t.Fatalf("Authorize returned success=false: %v", authResp)
	}
	if authResp.UserId == "" {
		t.Fatal("Authorize returned empty user_id")
	}
	if authResp.WrappedUserRootKey == "" {
		t.Fatal("Authorize returned empty wrapped_user_root_key")
	}
	if len(authResp.WrappedUserRootKey) < 64 {
		t.Fatalf("WrappedUserRootKey too short: %d", len(authResp.WrappedUserRootKey))
	}

	unwrappedKey, err := testCrypto.UnwrapForTransit(authResp.WrappedUserRootKey, transitPrivKey)
	if err != nil {
		t.Fatalf("Failed to unwrap transit key: %v", err)
	}
	if len(unwrappedKey) != 32 {
		t.Fatalf("Unwrapped key should be 32 bytes, got %d", len(unwrappedKey))
	}
	t.Logf("Authorized user: %s, unwrapped Ku (hex): %s", authResp.UserId, hex.EncodeToString(unwrappedKey))
}

func TestAuthorizeExternalProvider(t *testing.T) {
	transitKey, transitPrivKey := generateTransitKey(t)
	externalID := "ext-auth-" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000006", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	createResp, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   "",
		Password:   "",
		ExternalId: externalID,
		Provider:   "keycloak",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if !createResp.Success {
		t.Fatal("CreateUser returned success=false")
	}
	t.Logf("Created external user: %s", createResp.UserId)

	authToken := makeTestToken("00000000-0000-0000-0000-000000000006", testUserRootKey, transitKey)
	authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authToken))

	authResp, err := client.Authorize(authCtx, &pgrpc.AuthorizeRequest{
		AuthType: &pgrpc.AuthorizeRequest_Brokered{
			Brokered: &pgrpc.BrokeredAuth{
				Provider:   "keycloak",
				ExternalId: externalID,
			},
		},
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !authResp.Success {
		t.Fatalf("Authorize returned success=false: %v", authResp)
	}
	if authResp.UserId == "" {
		t.Fatal("Authorize returned empty user_id")
	}
	if authResp.WrappedUserRootKey == "" {
		t.Fatal("Authorize returned empty wrapped_user_root_key")
	}
	if len(authResp.WrappedUserRootKey) < 64 {
		t.Fatalf("WrappedUserRootKey too short: %d", len(authResp.WrappedUserRootKey))
	}

	unwrappedKey, err := testCrypto.UnwrapForTransit(authResp.WrappedUserRootKey, transitPrivKey)
	if err != nil {
		t.Fatalf("Failed to unwrap transit key: %v", err)
	}
	if len(unwrappedKey) != 32 {
		t.Fatalf("Unwrapped key should be 32 bytes, got %d", len(unwrappedKey))
	}
	t.Logf("Authorized external user: %s, unwrapped Ku (hex): %s", authResp.UserId, hex.EncodeToString(unwrappedKey))
}

func TestDeleteUserNonExistent(t *testing.T) {
	ctx := context.Background()

	resp, err := client.DeleteUser(ctx, &pgrpc.DeleteUserRequest{
		UserId: "99999999-9999-9999-9999-999999999999",
	})
	if err != nil {
		t.Logf("DeleteUser error: %v", err)
	}
	if resp != nil && resp.Success {
		t.Error("DeleteUser should return false for non-existent")
	}
}

func TestDeleteUserSuccess(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	username := "deluser" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000007", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	createResp, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "password123",
		ExternalId: "",
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if !createResp.Success {
		t.Fatal("CreateUser returned success=false")
	}
	userID := createResp.UserId
	t.Logf("Created user for deletion: %s", userID)

	delResp, err := client.DeleteUser(ctx, &pgrpc.DeleteUserRequest{
		UserId: userID,
	})
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	if !delResp.Success {
		t.Fatalf("DeleteUser returned success=false: %s", delResp.Message)
	}
	t.Logf("Deleted user: %s", userID)
}

func TestCreateMultipleUsers(t *testing.T) {
	transitKey, _ := generateTransitKey(t)

	token := makeTestToken("00000000-0000-0000-0000-000000000003", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	users := []string{
		"user1-" + uniqSuffix(),
		"user2-" + uniqSuffix(),
		"user3-" + uniqSuffix(),
	}

	createdIDs := make([]string, len(users))
	for i, username := range users {
		resp, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
			Username:   username,
			Password:   "password123",
			ExternalId: "",
			Provider:   "local",
		})
		if err != nil {
			t.Fatalf("CreateUser failed for %s: %v", username, err)
		}
		if !resp.Success {
			t.Fatalf("CreateUser returned success=false for %s", username)
		}
		createdIDs[i] = resp.UserId
		t.Logf("Created user %s: %s", username, resp.UserId)
	}

	for i, userID := range createdIDs {
		if userID == "" {
			t.Errorf("User %d has empty userID", i)
		}
	}

	uniqueIDs := make(map[string]bool)
	for _, userID := range createdIDs {
		if uniqueIDs[userID] {
			t.Errorf("Duplicate userID found: %s", userID)
		}
		uniqueIDs[userID] = true
	}

	t.Logf("Successfully created %d unique users", len(createdIDs))
}

func uniqSuffix() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b[:2])
}

func TestCreateUserAuditSuccess(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	username := "audituser" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000099", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	_, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "password123",
		ExternalId: "",
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	resp, err := client.GetAuditLogs(ctx, &pgrpc.GetAuditLogsRequest{
		Start: 0,
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs failed: %v", err)
	}
	if len(resp.Entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	lastEntry := resp.Entries[0]
	if lastEntry.EventType != "create_user" {
		t.Errorf("expected event_type create_user, got: %s", lastEntry.EventType)
	}
	if lastEntry.ActionStatus != "success" {
		t.Errorf("expected action_status success, got: %s", lastEntry.ActionStatus)
	}
}

func TestCreateUserAuditFailure(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	username := "auditfailuser" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000099", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	_, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "password123",
		ExternalId: "",
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	_, err = client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "password123",
		ExternalId: "",
		Provider:   "local",
	})
	if err == nil {
		t.Fatal("expected duplicate user error")
	}

	resp, err := client.GetAuditLogs(ctx, &pgrpc.GetAuditLogsRequest{
		Start: 0,
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs failed: %v", err)
	}
	if len(resp.Entries) < 2 {
		t.Fatalf("expected at least 2 audit entries, got: %d", len(resp.Entries))
	}
	if resp.Entries[0].EventType != "create_user" || resp.Entries[0].ActionStatus != "failure" {
		t.Errorf("expected last entry to be create_user failure")
	}
}

func TestAuthorizeAuditSuccess(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	username := "authaudit" + uniqSuffix()

	token := makeTestToken("00000000-0000-0000-0000-000000000099", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	_, err := client.CreateUser(ctx, &pgrpc.CreateUserRequest{
		Username:   username,
		Password:   "password123",
		ExternalId: "",
		Provider:   "local",
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	authToken := makeTestToken("00000000-0000-0000-0000-000000000099", testUserRootKey, transitKey)
	authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authToken))

	_, err = client.Authorize(authCtx, &pgrpc.AuthorizeRequest{
		AuthType: &pgrpc.AuthorizeRequest_Local{
			Local: &pgrpc.LocalAuth{
				Username: username,
				Password: "password123",
			},
		},
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	resp, err := client.GetAuditLogs(ctx, &pgrpc.GetAuditLogsRequest{
		Start: 0,
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs failed: %v", err)
	}
	if len(resp.Entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	lastEntry := resp.Entries[0]
	if lastEntry.EventType != "authorize" {
		t.Errorf("expected event_type authorize, got: %s", lastEntry.EventType)
	}
	if lastEntry.ActionStatus != "success" {
		t.Errorf("expected action_status success, got: %s", lastEntry.ActionStatus)
	}
}

func TestAuthorizeAuditFailure(t *testing.T) {
	transitKey, _ := generateTransitKey(t)
	token := makeTestToken("00000000-0000-0000-0000-000000000099", testUserRootKey, transitKey)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	_, err := client.Authorize(ctx, &pgrpc.AuthorizeRequest{
		AuthType: &pgrpc.AuthorizeRequest_Local{
			Local: &pgrpc.LocalAuth{
				Username: "nonexistentuser",
				Password: "wrongpassword",
			},
		},
	})
	if err == nil {
		t.Fatal("expected authorize failure")
	}

	resp, err := client.GetAuditLogs(ctx, &pgrpc.GetAuditLogsRequest{
		Start: 0,
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs failed: %v", err)
	}
	if len(resp.Entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	lastEntry := resp.Entries[0]
	if lastEntry.EventType != "authorize" {
		t.Errorf("expected event_type authorize, got: %s", lastEntry.EventType)
	}
	if lastEntry.ActionStatus != "failure" {
		t.Errorf("expected action_status failure, got: %s", lastEntry.ActionStatus)
	}
}
