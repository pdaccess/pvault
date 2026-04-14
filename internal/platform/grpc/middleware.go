package grpc

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func AuthInterceptor(s *Server) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		rawToken, err := s.extractToken(ctx)
		if err != nil {
			return nil, err
		}

		claims, err := s.parseJWTClaims(rawToken)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		ctx = context.WithValue(ctx, domain.ContextKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, domain.ContextKeyUserRootKey, claims.UserRootKey)
		ctx = context.WithValue(ctx, domain.ContextKeyTransitPublicKey, claims.TransitPublicKey)

		return handler(ctx, req)
	}
}

func (s *Server) extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", domain.ErrNoMetadata
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return "", domain.ErrNoAuthorizationHeader
	}

	parts := strings.SplitN(authHeader[0], " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", domain.ErrInvalidAuthorizationFormat
	}

	return parts[1], nil
}

func (s *Server) parseJWTClaims(tokenStr string) (*domain.UserClaims, error) {
	if s.jwksValidator != nil {
		return s.parseJWTClaimsJWKS(tokenStr)
	}
	return s.parseJWTClaimsHMAC(tokenStr)
}

func (s *Server) parseJWTClaimsHMAC(tokenStr string) (*domain.UserClaims, error) {
	mc := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, &mc, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	return extractUserClaims(mc)
}

func (s *Server) parseJWTClaimsJWKS(tokenStr string) (*domain.UserClaims, error) {
	mc, err := s.jwksValidator.Claims(tokenStr)
	if err != nil {
		return nil, err
	}
	return extractUserClaims(mc)
}

func extractUserClaims(mc jwt.MapClaims) (*domain.UserClaims, error) {
	userIDStr, ok := mc["user_uid"].(string)
	if !ok || userIDStr == "" {
		userIDStr, _ = mc["sub"].(string)
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user_uid claim: %w", err)
	}

	userRootTokenStr, _ := mc["x-urk"].(string)
	var userRootKey []byte
	if userRootTokenStr != "" {
		userRootKey, err = hex.DecodeString(userRootTokenStr)
		if err != nil {
			return nil, fmt.Errorf("invalid x-urk claim: %w", err)
		}
	}

	transitPubKeyStr, _ := mc["x-tpk"].(string)
	var transitPubKey []byte
	if transitPubKeyStr != "" {
		transitPubKey, err = hex.DecodeString(transitPubKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid x-tpk claim: %w", err)
		}
	}

	return &domain.UserClaims{UserID: userID, UserRootKey: userRootKey, TransitPublicKey: transitPubKey}, nil
}
