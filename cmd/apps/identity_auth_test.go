package apps_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"google.golang.org/grpc/metadata"

	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

func generateTransitKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generateTransitKey: %v", err)
	}
	return key.PublicKey().Bytes()
}

func TestCreateUserLocalProvider(t *testing.T) {
	transitKey := generateTransitKey(t)
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
	transitKey := generateTransitKey(t)
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

func TestChangePasswordNotImplemented(t *testing.T) {
	ctx := context.Background()

	resp, err := client.ChangePassword(ctx, &pgrpc.ChangePasswordRequest{
		Username:    "testuser",
		OldPassword: "oldpassword",
		NewPassword: "newpassword",
	})
	if err != nil {
		t.Logf("ChangePassword error: %v", err)
	}
	if resp != nil && resp.Success {
		t.Error("ChangePassword should not be implemented")
	}
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

func uniqSuffix() string {
	b := make([]byte, 4)
	rand.Read(b)
	return string(b[0])
}
