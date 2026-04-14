package apps_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pdaccess/pvault/cmd/apps"
	"github.com/pdaccess/pvault/internal/core/ports"
	pgrpc "github.com/pdaccess/pvault/internal/platform/grpc"
	pgrpcclient "github.com/pdaccess/pvault/pkg/api/v1"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// testJWTSecret is the HMAC-SHA256 key shared between the test server and test token minting.
var testJWTSecret = []byte("test-jwt-secret-32-bytes-long!!!")

var (
	server     *pgrpc.Server
	serverConn *grpc.ClientConn
	client     pgrpcclient.PVaultServiceClient
	pg         ports.SecretRepository
)

// makeTestToken mints a signed JWT with user_uid, x-urk, and x-tpk claims.
// userRootKey must be 32 bytes (AES-256). transitPubKey can be nil.
func makeTestToken(userID string, userRootKey []byte, transitPubKey []byte) string {
	claims := jwt.MapClaims{
		"user_uid": userID,
		"x-urk":    hex.EncodeToString(userRootKey),
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	if transitPubKey != nil {
		claims["x-tpk"] = hex.EncodeToString(transitPubKey)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(testJWTSecret)
	if err != nil {
		panic("makeTestToken: " + err.Error())
	}
	return signed
}

// withAuth attaches a signed JWT for the given userID to the outgoing context.
// It uses testUserRootKey from membership_test.go as the user root key.
func withAuth(ctx context.Context, userID string) context.Context {
	token := makeTestToken(userID, testUserRootKey, nil)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
}

func TestMain(m *testing.M) {
	storageKey := make([]byte, 32)
	rand.Read(storageKey)
	os.Setenv("PV_STORAGE_KEY", hex.EncodeToString(storageKey))

	ctx := context.Background()

	dbName := "pvault"
	dbUser := "postgres"
	dbPassword := "postgres"

	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("docker.io/postgres:17-alpine"),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(10*time.Second)),
	)
	if err != nil {
		panic("failed to start postgres container: " + err.Error())
	}

	connectionStr, err := postgresContainer.ConnectionString(ctx)
	if err != nil {
		panic("failed to get connection string: " + err.Error())
	}

	logger := zerolog.New(nil).Level(zerolog.ErrorLevel)
	testCtx := logger.With().Str("component", "test").Logger().WithContext(context.Background())

	server, pg, err = apps.StartServer(testCtx, "localhost:0", connectionStr, false, "", "", "", testJWTSecret)
	if err != nil {
		panic("failed to start server: " + err.Error())
	}

	time.Sleep(500 * time.Millisecond)

	serverAddr := server.Address()
	if serverAddr == "" {
		panic("server address not available")
	}

	serverConn, err = grpc.Dial(serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype("json")),
		grpc.WithBlock())
	if err != nil {
		panic("failed to dial server: " + err.Error())
	}

	client = pgrpcclient.NewPVaultServiceClient(serverConn)

	code := m.Run()

	if serverConn != nil {
		serverConn.Close()
	}
	if server != nil {
		server.Stop()
	}
	if postgresContainer != nil {
		postgresContainer.Terminate(ctx)
	}

	if code != 0 {
		// Tests failed but don't panic - test results are reported separately
	}
}
