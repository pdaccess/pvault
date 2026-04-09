package apps

import (
	"context"
	"crypto/rand"
	"os"
	"os/signal"
	"syscall"

	"github.com/pdaccess/pvault/internal/adapters/crypto"
	"github.com/pdaccess/pvault/internal/adapters/mock"
	"github.com/pdaccess/pvault/internal/adapters/pg"
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

	// Read JWT secret from environment; generate a random one if absent.
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = make([]byte, 32)
		if _, err := rand.Read(jwtSecret); err != nil {
			logger.Error().Err(err).Msg("failed to generate jwt secret")
			return
		}
	}

	server, _, err := StartServer(ctx, listenAddr, dbConnStr, tlsEnabled, tlsCertFile, tlsKeyFile, jwtSecret)
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

func StartServer(ctx context.Context, listenAddr, dbConnStr string, tlsEnabled bool, tlsCertFile, tlsKeyFile string, jwtSecret []byte) (*grpcsrv.Server, ports.SecretRepository, error) {
	storeageKey := make([]byte, 32)
	if _, err := rand.Read(storeageKey); err != nil {
		return nil, nil, err
	}

	var vaultService ports.VaultService
	var pgBackend ports.SecretRepository

	if dbConnStr != "" {
		var err error
		pgBackend, err = pg.New(dbConnStr)
		if err != nil {
			return nil, nil, err
		}
		cryptoService := crypto.NewAESGCMService(storeageKey)
		vaultService, err = service.New(pgBackend, cryptoService, mock.NewAllValidValidator())
		if err != nil {
			return nil, nil, err
		}
	} else {
		mockRepo := mock.New()
		mockCrypto := mock.NewCryptoService()
		svc, err := service.New(mockRepo, mockCrypto, mock.NewAllValidValidator())
		if err != nil {
			return nil, nil, err
		}
		vaultService = svc
	}

	var opts []grpcsrv.Option
	opts = append(opts, grpcsrv.WithAddress(listenAddr))
	opts = append(opts, grpcsrv.WithJWTSecret(jwtSecret))

	if tlsEnabled {
		opts = append(opts, grpcsrv.WithTLS(tlsCertFile, tlsKeyFile))
	}

	server := grpcsrv.New(vaultService, opts...)

	go func() {
		if err := server.Start(); err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("server error")
		}
	}()

	return server, pgBackend, nil
}
