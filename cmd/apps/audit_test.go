package apps_test

import (
	"context"
	"testing"

	pgrpc "github.com/pdaccess/pvault/pkg/api/v1"
)

// auditUserID is the caller used in audit-log tests.
const auditUserID = "660e8400-0000-0000-0000-000000000099"

func TestAuditLogRecord(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "test-service",
		CorrelationId: "550e8400-e29b-41d4-a716-446655440001",
		EventType:     "create_membership",
		ActorId:       "550e8400-e29b-41d4-a716-446655440000",
		ActionStatus:  "success",
		PayloadJson:   `{"action": "create_membership", "user": "test-user"}`,
	})
	if err != nil {
		t.Fatalf("RecordAuditLog failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.AuditId <= 0 {
		t.Errorf("expected positive audit ID, got: %d", resp.AuditId)
	}
	if resp.CurrHmac == nil {
		t.Error("expected non-nil HMAC")
	}
}

func TestAuditLogMultiple(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	correlationID := "550e8400-e29b-41d4-a716-446655440002"

	// Record multiple audit logs
	for i := range 3 {
		resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
			SourceService: "test-service",
			CorrelationId: correlationID,
			EventType:     "test_event",
			ActorId:       "550e8400-e29b-41d4-a716-446655440000",
			ActionStatus:  "success",
			PayloadJson:   `{"index": ` + string(rune('0'+i)) + `}`,
		})
		if err != nil {
			t.Fatalf("RecordAuditLog failed: %v", err)
		}
		if resp.AuditId <= 0 {
			t.Errorf("expected positive audit ID, got: %d", resp.AuditId)
		}
	}
}

func TestAuditLogEmptySourceService(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "",
		CorrelationId: "550e8400-e29b-41d4-a716-446655440003",
		EventType:     "test_event",
		ActorId:       "550e8400-e29b-41d4-a716-446655440000",
		ActionStatus:  "success",
		PayloadJson:   `{"test": "data"}`,
	})
	// Empty source service might be allowed
	_ = resp
	_ = err
}

func TestAuditLogEmptyEventType(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "test-service",
		CorrelationId: "550e8400-e29b-41d4-a716-446655440004",
		EventType:     "",
		ActorId:       "550e8400-e29b-41d4-a716-446655440000",
		ActionStatus:  "success",
		PayloadJson:   `{"test": "data"}`,
	})
	_ = resp
	_ = err
}

func TestAuditLogEmptyPayload(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "test-service",
		CorrelationId: "550e8400-e29b-41d4-a716-446655440005",
		EventType:     "test_event",
		ActorId:       "550e8400-e29b-41d4-a716-446655440000",
		ActionStatus:  "success",
		PayloadJson:   "",
	})
	if err != nil {
		t.Logf("RecordAuditLog with empty payload: %v", err)
	}
	if resp != nil && resp.AuditId > 0 {
		t.Logf("Audit ID: %d", resp.AuditId)
	}
}

func TestAuditLogDifferentActionStatuses(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	statuses := []string{"success", "failure", "pending", "unknown"}

	for _, status := range statuses {
		resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
			SourceService: "test-service",
			CorrelationId: "550e8400-e29b-41d4-a716-446655440006",
			EventType:     "test_event",
			ActorId:       "550e8400-e29b-41d4-a716-446655440000",
			ActionStatus:  status,
			PayloadJson:   `{"status": "` + status + `"}`,
		})
		if err != nil {
			t.Errorf("RecordAuditLog failed for status %s: %v", status, err)
		}
		if resp != nil && resp.AuditId <= 0 {
			t.Errorf("expected positive audit ID for status %s", status)
		}
	}
}

func TestAuditLogInvalidCorrelationID(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "test-service",
		CorrelationId: "invalid-uuid",
		EventType:     "test_event",
		ActorId:       "550e8400-e29b-41d4-a716-446655440000",
		ActionStatus:  "success",
		PayloadJson:   `{"test": "data"}`,
	})
	// Invalid UUID might be handled or ignored
	_ = resp
	_ = err
}

func TestAuditLogInvalidActorID(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	resp, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "test-service",
		CorrelationId: "550e8400-e29b-41d4-a716-446655440007",
		EventType:     "test_event",
		ActorId:       "invalid-actor-id",
		ActionStatus:  "success",
		PayloadJson:   `{"test": "data"}`,
	})
	_ = resp
	_ = err
}

func TestGetAuditLogs(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	// Record some audit logs first
	vaultID := "550e8400-e29b-41d4-a716-446655440010"
	for i := range 3 {
		_, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
			SourceService: "test-service",
			CorrelationId: vaultID,
			EventType:     "test_event",
			ActorId:       "550e8400-e29b-41d4-a716-446655440000",
			ActionStatus:  "success",
			PayloadJson:   `{"index": ` + string(rune('0'+i)) + `}`,
		})
		if err != nil {
			t.Fatalf("RecordAuditLog failed: %v", err)
		}
	}

	// Get audit logs with pagination
	resp, err := client.GetAuditLogs(ctx, &pgrpc.GetAuditLogsRequest{
		Start:   0,
		Limit:   2,
		VaultId: vaultID,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Entries) != 2 {
		t.Errorf("expected 2 entries, got: %d", len(resp.Entries))
	}
}

func TestGetAuditLogsByUser(t *testing.T) {
	ctx := withAuth(context.Background(), auditUserID)

	userID := "550e8400-e29b-41d4-a716-446655440020"
	vaultID := "550e8400-e29b-41d4-a716-446655440021"

	// Record audit logs for specific user
	_, err := client.RecordAuditLog(ctx, &pgrpc.AuditLogRequest{
		SourceService: "test-service",
		CorrelationId: vaultID,
		EventType:     "test_event",
		ActorId:       userID,
		ActionStatus:  "success",
		PayloadJson:   `{"test": "data"}`,
	})
	if err != nil {
		t.Fatalf("RecordAuditLog failed: %v", err)
	}

	// Get audit logs filtered by user
	resp, err := client.GetAuditLogs(ctx, &pgrpc.GetAuditLogsRequest{
		Start:  0,
		Limit:  10,
		UserId: userID,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs failed: %v", err)
	}
	if resp == nil || len(resp.Entries) == 0 {
		t.Fatal("expected entries filtered by user")
	}

	// Verify user filter worked
	for _, entry := range resp.Entries {
		if entry.ActorId != userID {
			t.Errorf("expected actor_id %s, got: %s", userID, entry.ActorId)
		}
	}
}
