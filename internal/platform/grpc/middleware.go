package grpc

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	commonDomain "github.com/pdaccess/commons/pkg/domain"
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
	mc := commonDomain.PdaccessClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, &mc, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	return extractUserClaimsFromMapClaims(mc)
}

func (s *Server) parseJWTClaimsJWKS(tokenStr string) (*domain.UserClaims, error) {
	claims, err := s.jwksValidator.Claims(tokenStr)
	if err != nil {
		return nil, err
	}
	return extractUserClaimsFromPdaccess(claims, tokenStr)
}

func extractUserClaimsFromPdaccess(claims *commonDomain.PdaccessClaims, tokenStr string) (*domain.UserClaims, error) {
	if claims.UserId == "" {
		return nil, fmt.Errorf("missing user_id claim")
	}

	userID, err := uuid.Parse(claims.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id claim: %w", err)
	}

	user, err := extractUserClaimsFromToken(tokenStr)
	if err != nil {
		return nil, err
	}

	return &domain.UserClaims{
		UserID:           userID,
		UserRootKey:      user.UserRootKey,
		TransitPublicKey: user.TransitPublicKey,
	}, nil
}

func extractUserClaimsFromToken(tokenString string) (*domain.UserClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}

	var rawClaims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &rawClaims); err != nil {
		return nil, fmt.Errorf("invalid token claims: %w", err)
	}

	var userRootKey []byte
	if urkRaw, ok := rawClaims["x-urk"]; ok {
		var urkStr string
		if err := json.Unmarshal(urkRaw, &urkStr); err == nil && urkStr != "" {
			userRootKey, err = hex.DecodeString(urkStr)
			if err != nil {
				return nil, fmt.Errorf("invalid x-urk claim: %w", err)
			}
		}
	}

	var transitPubKey []byte
	if tpkRaw, ok := rawClaims["x-tpk"]; ok {
		var tpkStr string
		if err := json.Unmarshal(tpkRaw, &tpkStr); err == nil && tpkStr != "" {
			transitPubKey, err = hex.DecodeString(tpkStr)
			if err != nil {
				return nil, fmt.Errorf("invalid x-tpk claim: %w", err)
			}
		}
	}

	return &domain.UserClaims{UserRootKey: userRootKey, TransitPublicKey: transitPubKey}, nil
}

func extractUserClaimsFromMapClaims(mc commonDomain.PdaccessClaims) (*domain.UserClaims, error) {

	var urkBytes []byte
	if mc.Urk != "" {
		urkBytes, _ = hex.DecodeString(mc.Urk)
	}

	var tpkBytes []byte
	if mc.Tpk != "" {
		tpkBytes, _ = hex.DecodeString(mc.Tpk)
	}
	return &domain.UserClaims{UserID: uuid.MustParse(mc.UserId),
		UserRootKey: urkBytes, TransitPublicKey: tpkBytes}, nil
}
