package grpc

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
	v1 "github.com/pdaccess/pvault/pkg/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Handler struct {
	v1.UnimplementedPVaultServiceServer
	vaultService ports.VaultService
}

func NewHandler(vaultService ports.VaultService) *Handler {
	return &Handler{vaultService: vaultService}
}

// callerFromContext extracts the authenticated caller's UUID and root key from
// the context values set by the JWT auth interceptor.
func callerFromContext(ctx context.Context) (uuid.UUID, []byte, error) {
	userID, ok := ctx.Value(domain.ContextKeyUserID).(uuid.UUID)
	if !ok {
		return uuid.Nil, nil, fmt.Errorf("user_id not in context")
	}
	userRootKey, ok := ctx.Value(domain.ContextKeyUserRootKey).([]byte)
	if !ok {
		return uuid.Nil, nil, fmt.Errorf("user_root_key not in context")
	}
	return userID, userRootKey, nil
}

func (h *Handler) CreateVault(ctx context.Context, req *v1.CreateVaultRequest) (*v1.CreateVaultResponse, error) {
	vaultID, err := uuid.Parse(req.VaultId)
	if err != nil {
		return &v1.CreateVaultResponse{Success: false, Message: "invalid vault_id"}, err
	}

	// Caller identity comes from JWT claims, not from the request body.
	userID, userRootKey, err := callerFromContext(ctx)
	if err != nil {
		return &v1.CreateVaultResponse{Success: false, Message: "unauthenticated"}, status.Error(codes.Unauthenticated, err.Error())
	}

	if err := h.vaultService.CreateVault(ctx, vaultID, userID, userRootKey); err != nil {
		return &v1.CreateVaultResponse{Success: false, Message: err.Error()}, err
	}
	return &v1.CreateVaultResponse{VaultId: req.VaultId, Success: true, Message: "vault created"}, nil
}

func (h *Handler) CreateMembership(ctx context.Context, req *v1.CreateMembershipRequest) (*v1.MembershipResponse, error) {
	// UserId / UserRootKey in request refer to the NEW MEMBER being added, not the caller.
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return &v1.MembershipResponse{Success: false, Message: "invalid user_id"}, err
	}

	vaultID, err := uuid.Parse(req.VaultId)
	if err != nil {
		return &v1.MembershipResponse{Success: false, Message: "invalid vault_id"}, err
	}

	err = h.vaultService.CreateMembership(ctx, userID, vaultID, req.UserRootKey, req.Role, req.Capabilities)
	if err != nil {
		return &v1.MembershipResponse{Success: false, Message: err.Error()}, err
	}

	return &v1.MembershipResponse{Success: true, Message: "membership created"}, nil
}

func (h *Handler) ListAuthorizedVaults(ctx context.Context, req *v1.ListVaultsRequest) (*v1.ListVaultsResponse, error) {
	userID, _, err := callerFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	vaultIDs, err := h.vaultService.ListAuthorizedVaults(ctx, userID)
	if err != nil {
		return nil, err
	}

	ids := make([]string, len(vaultIDs))
	for i, id := range vaultIDs {
		ids[i] = id.String()
	}
	return &v1.ListVaultsResponse{VaultIds: ids}, nil
}

func (h *Handler) ProtectSecret(ctx context.Context, req *v1.ProtectSecretRequest) (*v1.SecretResponse, error) {
	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, err
	}

	vaultID, err := uuid.Parse(req.VaultId)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, err
	}

	callerID, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, status.Error(codes.Unauthenticated, err.Error())
	}

	err = h.vaultService.ProtectSecret(ctx, callerID, secretID, vaultID, req.Plaintext)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, err
	}

	return &v1.SecretResponse{Success: true, SecretId: req.SecretId}, nil
}

func (h *Handler) UncoverSecret(ctx context.Context, req *v1.UncoverSecretRequest) (*v1.UncoverSecretResponse, error) {
	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return &v1.UncoverSecretResponse{Plaintext: ""}, err
	}

	vaultID, err := uuid.Parse(req.VaultId)
	if err != nil {
		return &v1.UncoverSecretResponse{Plaintext: ""}, err
	}

	callerID, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.UncoverSecretResponse{Plaintext: ""}, status.Error(codes.Unauthenticated, err.Error())
	}

	plaintext, err := h.vaultService.UncoverSecret(ctx, callerID, secretID, vaultID, req.Action)
	if err != nil {
		return &v1.UncoverSecretResponse{Plaintext: ""}, err
	}

	return &v1.UncoverSecretResponse{Plaintext: plaintext}, nil
}

func (h *Handler) RecordAuditLog(ctx context.Context, req *v1.AuditLogRequest) (*v1.AuditLogResponse, error) {
	correlationID, _ := uuid.Parse(req.CorrelationId)
	actorID, _ := uuid.Parse(req.ActorId)

	entry := &domain.AuditEntry{
		SourceService: req.SourceService,
		CorrelationID: correlationID,
		EventType:     req.EventType,
		ActorID:       actorID,
		ActionStatus:  req.ActionStatus,
		Payload:       map[string]any{"data": req.PayloadJson},
		CurrHMAC:      []byte{},
	}

	err := h.vaultService.RecordAudit(ctx, entry)
	if err != nil {
		return &v1.AuditLogResponse{AuditId: 0}, err
	}

	return &v1.AuditLogResponse{AuditId: 1, CurrHmac: entry.CurrHMAC}, nil
}
