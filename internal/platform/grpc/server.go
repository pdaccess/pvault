package grpc

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/pdaccess/pvault/internal/core/ports"
	v1 "github.com/pdaccess/pvault/pkg/api/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"

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

type Server struct {
	vaultService  ports.VaultService
	tlsEnabled    bool
	tlsCertFile   string
	tlsKeyFile    string
	listenAddr    string
	actualAddr    string
	jwtSecret     []byte         // HS256 symmetric key
	jwksValidator *JWKSValidator // RS256 JWKS validator; takes precedence over jwtSecret when set
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
		s.jwksValidator = NewJWKSValidator(url, keyID, refreshInterval)
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

	opts = append(opts, grpc.UnaryInterceptor(AuthInterceptor(s)))
	// JSON codec is registered but not forced - client uses CallContentSubtype

	s.grpcServer = grpc.NewServer(opts...)

	v1.RegisterPVaultServiceServer(s.grpcServer, grpc_adapter.NewHandler(s.vaultService))

	return s.grpcServer.Serve(lis)
}

func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}
