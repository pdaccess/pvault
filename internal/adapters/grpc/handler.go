package grpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	commonDomain "github.com/pdaccess/commons/pkg/domain"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
	v1 "github.com/pdaccess/pvault/pkg/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Handler struct {
	v1.UnimplementedPVaultServiceServer
	vaultService ports.VaultService
}

func NewHandler(vaultService ports.VaultService) *Handler {
	return &Handler{vaultService: vaultService}
}

func extractTransitPubKeyFromJWT(ctx context.Context) ([]byte, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 || authHeader[0] == "" {
		return nil, nil
	}

	tokenStr := authHeader[0]
	if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
		tokenStr = tokenStr[7:]
	}

	mc := commonDomain.PdaccessClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenStr, &mc)
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(mc.Tpk)
}

func (h *Handler) Authorize(ctx context.Context, req *v1.AuthorizeRequest) (*v1.AuthorizeResponse, error) {
	var username, password, externalID string
	var provider domain.IdentityProvider = domain.ProviderLocal

	if req.GetLocal() != nil {
		username = req.GetLocal().Username
		password = req.GetLocal().Password
		provider = domain.ProviderLocal
	} else if req.GetBrokered() != nil {
		provider = domain.IdentityProvider(req.GetBrokered().Provider)
		externalID = req.GetBrokered().ExternalId
	}

	transitPubKey, _ := extractTransitPubKeyFromJWT(ctx)
	userID, wrappedKU, err := h.vaultService.Authorize(ctx, provider, username, password, externalID, transitPubKey)
	if err != nil {
		return &v1.AuthorizeResponse{Success: false}, err
	}

	return &v1.AuthorizeResponse{
		UserId:             userID,
		WrappedUserRootKey: wrappedKU,
		Success:            true,
	}, nil
}

func (h *Handler) CreateUser(ctx context.Context, req *v1.CreateUserRequest) (*v1.CreateUserResponse, error) {
	provider := domain.IdentityProvider(req.Provider)

	transitPubKey, _ := extractTransitPubKeyFromJWT(ctx)
	userID, wrappedKU, err := h.vaultService.CreateUser(ctx, req.Username, req.Password, req.GetExternalId(), provider, transitPubKey)
	if err != nil {
		return &v1.CreateUserResponse{Success: false}, err
	}

	return &v1.CreateUserResponse{
		UserId:             userID,
		WrappedUserRootKey: wrappedKU,
		Success:            true,
	}, nil
}

func (h *Handler) ChangePassword(ctx context.Context, req *v1.ChangePasswordRequest) (*v1.UserResponse, error) {
	_, _, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.UserResponse{Success: false, Message: "unauthenticated"}, status.Error(codes.Unauthenticated, err.Error())
	}

	if err := h.vaultService.ChangePassword(ctx, req.Username, req.OldPassword, req.NewPassword); err != nil {
		return &v1.UserResponse{Success: false, Message: err.Error()}, err
	}

	return &v1.UserResponse{Success: true, Message: "password changed"}, nil
}

func (h *Handler) DeleteUser(ctx context.Context, req *v1.DeleteUserRequest) (*v1.UserResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return &v1.UserResponse{Success: false, Message: "invalid user_id"}, err
	}

	if err := h.vaultService.DeleteUser(ctx, userID); err != nil {
		return &v1.UserResponse{Success: false, Message: err.Error()}, err
	}

	return &v1.UserResponse{Success: true, Message: "user deleted"}, nil
}

// callerFromContext extracts the authenticated caller's UUID, root key, and transit
// public key from the context values set by the JWT auth interceptor.
// Returns nil for userRootKey/transitPubKey if not available.
func callerFromContext(ctx context.Context) (uuid.UUID, []byte, []byte, error) {
	userID, ok := ctx.Value(domain.ContextKeyUserID).(uuid.UUID)
	if !ok {
		return uuid.Nil, nil, nil, fmt.Errorf("user_id not in context")
	}
	userRootKey, _ := ctx.Value(domain.ContextKeyUserRootKey).([]byte)
	transitPubKey, _ := ctx.Value(domain.ContextKeyTransitPublicKey).([]byte)
	return userID, userRootKey, transitPubKey, nil
}

func (h *Handler) CreateVault(ctx context.Context, req *v1.CreateVaultRequest) (*v1.CreateVaultResponse, error) {
	vaultID, err := uuid.Parse(req.VaultId)
	if err != nil {
		return &v1.CreateVaultResponse{Success: false, Message: "invalid vault_id"}, err
	}

	userID, userRootKey, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.CreateVaultResponse{Success: false, Message: "unauthenticated"}, status.Error(codes.Unauthenticated, err.Error())
	}

	if err := h.vaultService.CreateVault(ctx, vaultID, userID, userRootKey); err != nil {
		return &v1.CreateVaultResponse{Success: false, Message: err.Error()}, err
	}
	return &v1.CreateVaultResponse{VaultId: req.VaultId, Success: true, Message: "vault created"}, nil
}

func (h *Handler) CreateMembership(ctx context.Context, req *v1.CreateMembershipRequest) (*v1.MembershipResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return &v1.MembershipResponse{Success: false, Message: "invalid user_id"}, err
	}

	vaultID, err := uuid.Parse(req.VaultId)
	if err != nil {
		return &v1.MembershipResponse{Success: false, Message: "invalid vault_id"}, err
	}

	callerID, userRootKey, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.MembershipResponse{Success: false, Message: "unauthenticated"}, status.Error(codes.Unauthenticated, err.Error())
	}

	err = h.vaultService.CreateMembership(ctx, callerID, userID, vaultID, userRootKey, domain.VaultRole(req.Role))
	if err != nil {
		return &v1.MembershipResponse{Success: false, Message: err.Error()}, err
	}

	return &v1.MembershipResponse{Success: true, Message: "membership created"}, nil
}

func (h *Handler) ListAuthorizedVaults(ctx context.Context, req *v1.ListVaultsRequest) (*v1.ListVaultsResponse, error) {
	userID, _, _, err := callerFromContext(ctx)
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

	callerID, _, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, status.Error(codes.Unauthenticated, err.Error())
	}

	caps := domain.CapabilitiesFromStrings(req.GetCapabilities())
	// Version is always auto-incremented on the service layer
	err = h.vaultService.ProtectSecret(ctx, callerID, secretID, vaultID, req.Plaintext, caps)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, err
	}

	// Get latest version from service
	var savedVer int32 = 1
	latest, ok := h.vaultService.(interface {
		GetLatestSecretVersion(context.Context, uuid.UUID) (int, error)
	})
	if ok {
		if v, err := latest.GetLatestSecretVersion(ctx, secretID); err == nil {
			savedVer = int32(v)
		}
	}

	return &v1.SecretResponse{Success: true, SecretId: req.SecretId, Version: savedVer}, nil
}

func (h *Handler) UncoverSecret(ctx context.Context, req *v1.UncoverSecretRequest) (*v1.UncoverSecretResponse, error) {
	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return &v1.UncoverSecretResponse{Plaintext: ""}, err
	}

	callerID, _, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.UncoverSecretResponse{Plaintext: ""}, status.Error(codes.Unauthenticated, err.Error())
	}

	var version *int
	if v := req.GetVersion(); v > 0 {
		version = new(int)
		*version = int(v)
	}
	action := domain.Capability(req.Action)
	plaintext, returnedVersion, err := h.vaultService.UncoverSecret(ctx, callerID, secretID, action, version)
	if err != nil {
		return &v1.UncoverSecretResponse{Plaintext: ""}, err
	}

	return &v1.UncoverSecretResponse{Plaintext: plaintext, Version: int32(returnedVersion)}, nil
}

func (h *Handler) DeleteSecret(ctx context.Context, req *v1.DeleteSecretRequest) (*v1.DeleteSecretResponse, error) {
	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return &v1.DeleteSecretResponse{Success: false, SecretId: req.SecretId, Message: "invalid secret_id"}, err
	}

	callerID, _, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.DeleteSecretResponse{Success: false, Message: "unauthenticated"}, status.Error(codes.Unauthenticated, err.Error())
	}

	if err := h.vaultService.DeleteSecret(ctx, callerID, secretID); err != nil {
		return &v1.DeleteSecretResponse{Success: false, Message: err.Error()}, err
	}

	return &v1.DeleteSecretResponse{Success: true, SecretId: req.SecretId, Message: "secret deleted"}, nil
}

func (h *Handler) UpdateSecretCapabilities(ctx context.Context, req *v1.UpdateSecretCapabilitiesRequest) (*v1.SecretResponse, error) {
	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, err
	}

	targetUserID, err := uuid.Parse(req.UserId)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, err
	}

	callerID, _, _, err := callerFromContext(ctx)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, status.Error(codes.Unauthenticated, err.Error())
	}

	caps := domain.CapabilitiesFromStrings(req.Capabilities)
	err = h.vaultService.UpdateSecretCapabilities(ctx, callerID, targetUserID, secretID, caps)
	if err != nil {
		return &v1.SecretResponse{Success: false, SecretId: req.SecretId}, err
	}

	return &v1.SecretResponse{Success: true, SecretId: req.SecretId}, nil
}

func (h *Handler) RecordAuditLog(ctx context.Context, req *v1.AuditLogRequest) (*v1.AuditLogResponse, error) {
	correlationID, _ := uuid.Parse(req.CorrelationId)
	actorID, _ := uuid.Parse(req.ActorId)

	entry := &domain.AuditEntry{
		SourceService: req.SourceService,
		CorrelationID: correlationID,
		EventType:     domain.EventType(req.EventType),
		ActorID:       actorID,
		ActionStatus:  req.ActionStatus,
		Payload:       domain.AuditPayload{"data": req.PayloadJson},
		CurrHMAC:      []byte{},
	}

	err := h.vaultService.RecordAudit(ctx, entry)
	if err != nil {
		return &v1.AuditLogResponse{AuditId: 0}, err
	}

	return &v1.AuditLogResponse{AuditId: 1, CurrHmac: entry.CurrHMAC}, nil
}

func (h *Handler) GetAuditLogs(ctx context.Context, req *v1.GetAuditLogsRequest) (*v1.GetAuditLogsResponse, error) {
	var userID, vaultID *uuid.UUID
	if req.UserId != "" {
		if parsed, err := uuid.Parse(req.UserId); err == nil {
			userID = &parsed
		}
	}
	if req.VaultId != "" {
		if parsed, err := uuid.Parse(req.VaultId); err == nil {
			vaultID = &parsed
		}
	}

	entries, err := h.vaultService.GetAuditEntries(ctx, int(req.Start), int(req.Limit), userID, vaultID)
	if err != nil {
		return nil, err
	}

	var result []*v1.AuditLogEntry
	for _, e := range entries {
		payload, _ := json.Marshal(e.Payload)
		result = append(result, &v1.AuditLogEntry{
			Id:            e.ID,
			SourceService: e.SourceService,
			CorrelationId: e.CorrelationID.String(),
			EventType:     string(e.EventType),
			ActorId:       e.ActorID.String(),
			ActionStatus:  e.ActionStatus,
			PayloadJson:   string(payload),
			UpdatedAt:     e.UpdatedAt.Unix(),
		})
	}
	return &v1.GetAuditLogsResponse{Entries: result}, nil
}
