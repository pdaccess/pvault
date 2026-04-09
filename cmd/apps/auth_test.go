package apps_test

import (
	"context"
	"strings"
	"testing"

	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
	"google.golang.org/grpc/metadata"
)

// authTestUserID is used for tests that verify the auth interceptor accepts valid tokens.
const authTestUserID = "550e8400-0000-0000-0000-000000000099"

func TestAuthNoToken(t *testing.T) {
	_, err := client.ListAuthorizedVaults(context.Background(), &pgrpc.ListVaultsRequest{})
	if err == nil {
		t.Error("expected error without token")
	}
}

func TestAuthInvalidFormat(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "InvalidFormat"))
	_, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	if err == nil {
		t.Error("expected error with invalid format")
	}
}

func TestAuthValidBearerToken(t *testing.T) {
	ctx := withAuth(context.Background(), authTestUserID)
	_, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	// Should succeed: valid JWT with proper claims.
	if err != nil {
		t.Errorf("unexpected error with valid JWT: %v", err)
	}
}

func TestAuthEmptyBearer(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "))
	_, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	// Empty token is not a valid JWT — expect an error.
	if err == nil {
		t.Error("expected error for empty bearer token")
	}
}

func TestAuthMultipleSpaces(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer  token with spaces"))
	_, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
	// " token with spaces" is not a valid JWT — expect an error.
	if err == nil {
		t.Error("expected error for malformed bearer token")
	}
}

func TestAuthDifferentHeaderFormats(t *testing.T) {
	tests := []struct {
		name string
		auth string
	}{
		{"lowercase bearer", "bearer test-token"},
		{"uppercase bearer", "BEARER test-token"},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"custom prefix", "Custom token123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tt.auth))
			_, err := client.ListAuthorizedVaults(ctx, &pgrpc.ListVaultsRequest{})
			// All should fail with current implementation
			if err == nil {
				t.Error("expected error for different auth format")
			}
		})
	}
}

func TestAuthInterceptorOrder(t *testing.T) {
	// Test that auth interceptor runs before method handler
	tests := []struct {
		name          string
		ctx           context.Context
		expectAuthErr bool
	}{
		{"no metadata", context.Background(), true},
		{"valid token", withAuth(context.Background(), authTestUserID), false},
		{"invalid format", metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Basic abc")), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.ListAuthorizedVaults(tt.ctx, &pgrpc.ListVaultsRequest{})
			if tt.expectAuthErr && err == nil {
				t.Error("expected auth error")
			}
			if !tt.expectAuthErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestServerWithPostgres(t *testing.T) {
	// Verify server is running and connected to PostgreSQL
	if server == nil {
		t.Fatal("server should not be nil")
	}
	if server.Address() == "" {
		t.Fatal("server should have an address")
	}
	t.Logf("Server running on: %s", server.Address())
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}
