package grpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/adapters/jwks"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
	v1 "github.com/pdaccess/pvault/pkg/api/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpc_adapter "github.com/pdaccess/pvault/internal/adapters/grpc"
)

// JSONCodec for gRPC JSON encoding
type JSONCodec struct{}

func (c *JSONCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (c *JSONCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (c *JSONCodec) Name() string {
	return "json"
}

func init() {
	encoding.RegisterCodec(&JSONCodec{})
}

// jwksKey is a single JSON Web Key from a JWKS endpoint.
type jwksKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"` // base64url-encoded RSA modulus
	E   string `json:"e"` // base64url-encoded RSA exponent
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

type Server struct {
	vaultService  ports.VaultService
	tlsEnabled    bool
	tlsCertFile   string
	tlsKeyFile    string
	listenAddr    string
	actualAddr    string
	jwtSecret     []byte              // HS256 symmetric key
	jwksValidator ports.JWKSValidator // RS256 JWKS validator; takes precedence over jwtSecret when set
	grpcServer    *grpc.Server
}

type Option func(*Server)

func WithTLS(certFile, keyFile string) Option {
	return func(s *Server) {
		s.tlsEnabled = true
		s.tlsCertFile = certFile
		s.tlsKeyFile = keyFile
	}
}

func WithAddress(addr string) Option {
	return func(s *Server) {
		s.listenAddr = addr
	}
}

// WithJWTSecret sets the HMAC-SHA256 key used to validate and parse incoming JWTs.
func WithJWTSecret(key []byte) Option {
	return func(s *Server) {
		s.jwtSecret = key
	}
}

// WithJWKSURL configures the server to validate RS256 JWTs via the given JWKS endpoint.
// When set, HMAC validation is not used.
func WithJWKSURL(url string, keyID string, refreshInterval time.Duration) Option {
	return func(s *Server) {
		s.jwksValidator = jwks.NewValidator(url, keyID, refreshInterval)
	}
}

func (s *Server) Address() string {
	return s.actualAddr
}

func New(vaultService ports.VaultService, opts ...Option) *Server {
	s := &Server{
		vaultService: vaultService,
		listenAddr:   ":50051",
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *Server) Start() error {
	log.Info().Str("address", s.listenAddr).Msg("starting gRPC server")

	lis, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.actualAddr = lis.Addr().String()
	log.Info().Str("listening", s.actualAddr).Msg("gRPC server listening")

	opts := []grpc.ServerOption{}

	if s.tlsEnabled {
		creds, err := credentials.NewServerTLSFromFile(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			return fmt.Errorf("TLS setup: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Info().Msg("TLS enabled")
	} else {
		opts = append(opts, grpc.Creds(insecure.NewCredentials()))
		log.Info().Msg("TLS disabled (using insecure credentials)")
	}

	opts = append(opts, grpc.UnaryInterceptor(s.authInterceptor))
	// opts = append(opts, grpc.ForceServerCodec(&JSONCodec{}))

	s.grpcServer = grpc.NewServer(opts...)

	v1.RegisterPVaultServiceServer(s.grpcServer, grpc_adapter.NewHandler(s.vaultService))

	return s.grpcServer.Serve(lis)
}

func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

func (s *Server) authInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
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

	return handler(ctx, req)
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

// parseJWTClaims dispatches to JWKS (RS256) or HMAC (HS256) based on configuration.
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

// extractUserClaims reads user_uid and user_root_token from JWT map claims.
// Falls back to "sub" claim if user_uid is not present (for Keycloak compatibility).
func extractUserClaims(mc jwt.MapClaims) (*domain.UserClaims, error) {
	userIDStr, ok := mc["user_uid"].(string)
	if !ok || userIDStr == "" {
		userIDStr, _ = mc["sub"].(string)
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user_uid claim: %w", err)
	}

	userRootTokenStr, _ := mc["user_root_token"].(string)
	log.Debug().Msgf("extractUserClaims: user_root_token claim = %q %v\n", userRootTokenStr, mc)
	var userRootKey []byte
	if userRootTokenStr != "" {
		userRootKey, err = hex.DecodeString(userRootTokenStr)
		if err != nil {
			return nil, fmt.Errorf("invalid user_root_token claim: %w", err)
		}
		log.Debug().Msgf("extractUserClaims: decoded userRootKey %s length = %d\n", string(userRootKey), len(userRootKey))
	}

	return &domain.UserClaims{UserID: userID, UserRootKey: userRootKey}, nil
}
