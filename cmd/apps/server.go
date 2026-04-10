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
	"github.com/pdaccess/pvault/internal/adapters/jwks"
	"github.com/pdaccess/pvault/internal/adapters/mock"
	"github.com/pdaccess/pvault/internal/adapters/pg"
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/pdaccess/pvault/internal/core/service"
	grpcsrv "github.com/pdaccess/pvault/internal/platform/grpc"
	"github.com/rs/zerolog"
	"github.com/thatisuday/commando"
)

func getEnvOrFlag(envVar, flagValue string) string {
	if val := os.Getenv(envVar); val != "" {
		return val
	}
	return flagValue
}

func CreateServer(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	listenAddr := os.Getenv("PV_LISTEN")
	if listenAddr == "" {
		listenAddr, _ = flags["listen"].GetString()
	}

	dbConnStr := os.Getenv("PV_DB")
	if dbConnStr == "" {
		dbConnStr = "postgres://postgres:postgres@postgres:5432/pvault"
	}

	jwksURL := os.Getenv("PV_JWKS")
	if jwksURL == "" {
		jwksURL, _ = flags["jwks"].GetString()
	}

	tlsEnabled, _ := flags["tls"].GetBool()
	tlsCertFile, _ := flags["tls-cert"].GetString()
	tlsCertFile = getEnvOrFlag("PV_TLS_CERT", tlsCertFile)
	tlsKeyFile, _ := flags["tls-key"].GetString()
	tlsKeyFile = getEnvOrFlag("PV_TLS_KEY", tlsKeyFile)

	logLevel, _ := flags["log-level"].GetString()
	logLevel = getEnvOrFlag("PV_LOG_LEVEL", logLevel)

	jwksRefreshInterval := getEnvOrFlag("PV_JWKS_REFRESH", "5m")
	refreshDuration, err := time.ParseDuration(jwksRefreshInterval)
	if err != nil {
		refreshDuration = 5 * time.Minute
	}

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
		tokenValidator = jwks.NewValidator(jwksURL, "", refreshDuration)
		logger.Info().Str("jwks", jwksURL).Str("refresh", jwksRefreshInterval).Msg("using JWKS token validator")
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
		opts = append(opts, grpcsrv.WithJWKSURL(jwksURL, "", 5*time.Minute))
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
