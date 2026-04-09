package apps

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pdaccess/pvault/internal/adapters/crypto"
	"github.com/pdaccess/pvault/internal/adapters/mock"
	"github.com/pdaccess/pvault/internal/adapters/pg"
	"github.com/pdaccess/pvault/internal/adapters/token/jwks"
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/pdaccess/pvault/internal/core/service"
	grpcsrv "github.com/pdaccess/pvault/internal/platform/grpc"
	"github.com/rs/zerolog"
	"github.com/thatisuday/commando"
)

func CreateServer(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	listenAddr, _ := flags["listen"].GetString()
	dbConnStr, _ := flags["db"].GetString()
	tlsEnabled, _ := flags["tls"].GetBool()
	tlsCertFile, _ := flags["tls-cert"].GetString()
	tlsKeyFile, _ := flags["tls-key"].GetString()
	logLevel, _ := flags["log-level"].GetString()
	jwksURL, _ := flags["jwks"].GetString()

	logger := zerolog.New(os.Stdout).Level(zerolog.InfoLevel)
	switch logLevel {
	case "debug":
		logger = logger.Level(zerolog.DebugLevel)
	case "warn":
		logger = logger.Level(zerolog.WarnLevel)
	case "error":
		logger = logger.Level(zerolog.ErrorLevel)
	}

	ctx := logger.With().Str("component", "server").Logger().WithContext(context.Background())

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = make([]byte, 32)
		if _, err := rand.Read(jwtSecret); err != nil {
			logger.Error().Err(err).Msg("failed to generate jwt secret")
			return
		}
	}

	var tokenValidator ports.TokenValidator
	if jwksURL != "" {
		tokenValidator = jwks.New(jwksURL, 5*time.Minute)
		logger.Info().Str("jwks", jwksURL).Msg("using JWKS token validator")
	} else {
		tokenValidator = mock.NewAllValidValidator()
		logger.Warn().Msg("no JWKS URL provided, using mock validator")
	}

	server, _, err := StartServer(ctx, listenAddr, dbConnStr, tlsEnabled, tlsCertFile, tlsKeyFile, jwksURL, jwtSecret, tokenValidator)
	if err != nil {
		logger.Error().Err(err).Msg("failed to start server")
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info().Msg("shutting down")
		server.Stop()
	}()

	logger.Info().Str("address", server.Address()).Msg("gRPC server running")
	<-sigCh
}

func StartServer(ctx context.Context, listenAddr, dbConnStr string, tlsEnabled bool, tlsCertFile, tlsKeyFile string, jwksURL string, jwtSecret []byte, tokenValidator ports.TokenValidator) (*grpcsrv.Server, ports.SecretRepository, error) {
	logger := zerolog.Ctx(ctx)

	storeageKey := make([]byte, 32)
	if _, err := rand.Read(storeageKey); err != nil {
		return nil, nil, fmt.Errorf("generate storage key: %w", err)
	}

	logger.Info().Msg("initializing storage key")

	var vaultService ports.VaultService
	var pgBackend ports.SecretRepository

	if dbConnStr != "" {
		logger.Info().Str("db", dbConnStr).Msg("connecting to database")
		var err error
		pgBackend, err = pg.New(dbConnStr)
		if err != nil {
			return nil, nil, fmt.Errorf("connect to database: %w", err)
		}
		logger.Info().Msg("database connected")

		logger.Info().Msg("initializing crypto service")
		cryptoService := crypto.NewAESGCMService(storeageKey)
		vaultService, err = service.New(pgBackend, cryptoService)
		if err != nil {
			return nil, nil, fmt.Errorf("create vault service: %w", err)
		}
	} else {
		logger.Info().Msg("using in-memory repository")
		mockRepo := mock.New()
		mockCrypto := mock.NewCryptoService()
		svc, err := service.New(mockRepo, mockCrypto)
		if err != nil {
			return nil, nil, fmt.Errorf("create vault service: %w", err)
		}
		vaultService = svc
	}

	logger.Info().Msg("vault service initialized")

	var opts []grpcsrv.Option
	opts = append(opts, grpcsrv.WithAddress(listenAddr))
	logger.Info().Str("address", listenAddr).Msg("gRPC server configuration")

	if jwksURL != "" {
		opts = append(opts, grpcsrv.WithJWKSURL(jwksURL))
		logger.Info().Str("jwks", jwksURL).Msg("using JWKS token validation")
	} else {
		opts = append(opts, grpcsrv.WithJWTSecret(jwtSecret))
		logger.Info().Msg("using HMAC token validation")
	}

	if tlsEnabled {
		opts = append(opts, grpcsrv.WithTLS(tlsCertFile, tlsKeyFile))
		logger.Info().Msg("TLS enabled")
	} else {
		logger.Info().Msg("TLS disabled (using insecure credentials)")
	}

	logger.Info().Msg("creating gRPC server")
	server := grpcsrv.New(vaultService, opts...)

	go func() {
		if err := server.Start(); err != nil {
			logger.Error().Err(err).Msg("gRPC server error")
		}
	}()

	logger.Info().Str("address", server.Address()).Msg("gRPC server started")

	return server, pgBackend, nil
}
