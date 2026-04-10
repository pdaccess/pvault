package apps

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/pdaccess/pvault/pkg/api/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/thatisuday/commando"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const tokenFileName = ".pvault/token"

func ConnectLogin(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}

	log.Logger = zerolog.New(output).With().Timestamp().Logger()

	keycloakURL, _ := flags["keycloak"].GetString()
	clientID, _ := flags["client-id"].GetString()
	clientSecret, _ := flags["client-secret"].GetString()

	const keycloakDefault = "http://localhost:8180"
	const clientIDDefault = "pvault-client"
	const clientSecretDefault = "pvault-client-secret"

	if keycloakURL == "" {
		keycloakURL = keycloakDefault
	}
	if clientID == "" {
		clientID = clientIDDefault
	}
	if clientSecret == "" {
		clientSecret = clientSecretDefault
	}

	token, err := loginWithPKCE(keycloakURL, clientID, clientSecret)
	if err != nil {
		log.Info().Msgf("Login failed: %v\n", err)
		return
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Info().Msgf("Failed to get home directory: %v\n", err)
		return
	}

	tokenPath := filepath.Join(homeDir, tokenFileName)
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		log.Info().Msgf("Failed to create token directory: %v\n", err)
		return
	}

	data, err := json.Marshal(token)
	if err != nil {
		log.Info().Msgf("Failed to marshal token: %v\n", err)
		return
	}

	if err := os.WriteFile(tokenPath, data, 0600); err != nil {
		log.Info().Msgf("Failed to save token: %v\n", err)
		return
	}

	log.Info().Msgf("Login successful! Token saved to %s\n", tokenPath)
	log.Info().Msgf("Token expires in %d seconds\n", token.ExpiresIn)

	parts := strings.Split(token.AccessToken, ".")
	if len(parts) >= 2 {
		payload := parts[1]
		padding := 4 - len(payload)%4
		if padding != 4 {
			payload += strings.Repeat("=", padding)
		}
		decoded, err := base64.URLEncoding.DecodeString(payload)
		if err == nil {
			var claims map[string]interface{}
			json.Unmarshal(decoded, &claims)
			if username, ok := claims["preferred_username"].(string); ok {
				log.Info().Msgf("Username: %s\n", username)
			}
			if sub, ok := claims["sub"].(string); ok {
				log.Info().Msgf("User ID: %s\n", sub)
			}
		}
	}
}

// Helpers for PKCE
func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func generateCodeChallenge(verifier string) string {
	sha := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])
}

func loginWithPKCE(url, clientID, clientSecret string) (*oauth2.Token, error) {

	ctx := context.Background()

	conf := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  url + "/realms/pvault/protocol/openid-connect/auth",
			TokenURL: url + "/realms/pvault/protocol/openid-connect/token",
		},
		RedirectURL:  "http://localhost:63081/callback",
		Scopes:       []string{"openid", "profile"},
		ClientSecret: clientSecret,
	}

	storedToken, err := GetStoredToken()
	tokenSource := conf.TokenSource(ctx, storedToken)
	refreshedToken, err := tokenSource.Token()
	if err == nil {
		return refreshedToken, nil
	}

	// 1. Generate PKCE Verifier and Challenge
	codeVerifier := generateRandomString(64)
	codeChallenge := generateCodeChallenge(codeVerifier)

	// 2. Create the Auth URL with PKCE params
	authURL := conf.AuthCodeURL("state-token",
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// 3. Start a local server to capture the callback code
	codeChan := make(chan string)
	server := &http.Server{Addr: ":63081"}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		fmt.Fprintf(w, "Login successful! You can close this window.")
		codeChan <- code
	})

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Error().Msgf("Server failed: %v", err)
		}
	}()

	log.Info().Msgf("Please log in at this URL:%s", authURL)

	// 4. Wait for the code and exchange it for a token
	authCode := <-codeChan
	token, err := conf.Exchange(ctx, authCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		log.Error().Msgf("Token exchange failed: %v", err)
	}

	fmt.Println("---------------------------")
	fmt.Println("Access Token with Custom Claim:")
	fmt.Println(token.AccessToken)

	server.Shutdown(ctx)

	return token, nil
}

func GetStoredToken() (*oauth2.Token, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	tokenPath := filepath.Join(homeDir, tokenFileName)
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}

	var token oauth2.Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	return &token, nil
}

func ConnectCreateVault(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := GetStoredToken()
	vaultID, _ := flags["vault-id"].GetString()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Info().Msgf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.CreateVault(withAuth(ctx, token), &v1.CreateVaultRequest{
		VaultId: vaultID,
	})
	if err != nil {
		log.Info().Msgf("Error: %v\n", err)
		return
	}
	log.Info().Msgf("Success: %v, Message: %s\n", resp.Success, resp.Message)
}

func ConnectCreateMembership(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := GetStoredToken()
	userID, _ := flags["user-id"].GetString()
	vaultID, _ := flags["vault-id"].GetString()
	userRootKey, _ := flags["user-root-key"].GetString()
	role, _ := flags["role"].GetString()

	userRootKeyBytes, err := hex.DecodeString(userRootKey)
	if err != nil {
		log.Info().Msgf("Invalid user-root-key: %v\n", err)
		return
	}

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Info().Msgf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.CreateMembership(withAuth(ctx, token), &v1.CreateMembershipRequest{
		UserId:      userID,
		VaultId:     vaultID,
		UserRootKey: userRootKeyBytes,
		Role:        role,
	})
	if err != nil {
		log.Info().Msgf("Error: %v\n", err)
		return
	}
	log.Info().Msgf("Success: %v, Message: %s\n", resp.Success, resp.Message)
}

func ConnectListVaults(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := GetStoredToken()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Info().Msgf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ListAuthorizedVaults(withAuth(ctx, token), &v1.ListVaultsRequest{})
	if err != nil {
		log.Info().Msgf("Error: %v\n", err)
		return
	}
	log.Info().Msgf("Vault IDs: %v\n", resp.VaultIds)
}

func ConnectProtectSecret(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	secretID, _ := flags["secret-id"].GetString()
	vaultID, _ := flags["vault-id"].GetString()
	plaintext, _ := flags["plaintext"].GetString()

	token, _ := GetStoredToken()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Info().Msgf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ProtectSecret(withAuth(ctx, token), &v1.ProtectSecretRequest{
		SecretId:  secretID,
		VaultId:   vaultID,
		Plaintext: plaintext,
	})
	if err != nil {
		log.Info().Msgf("Error: %v\n", err)
		return
	}
	log.Info().Msgf("Success: %v, SecretID: %s\n", resp.Success, resp.SecretId)
}

func ConnectUncoverSecret(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()

	secretID, _ := flags["secret-id"].GetString()
	action, _ := flags["action"].GetString()

	token, _ := GetStoredToken()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Info().Msgf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.UncoverSecret(withAuth(ctx, token), &v1.UncoverSecretRequest{
		SecretId: secretID,
		Action:   action,
	})
	if err != nil {
		log.Info().Msgf("Error: %v\n", err)
		return
	}
	log.Info().Msgf("Plaintext: %s\n", resp.Plaintext)
}

func ConnectRecordAudit(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	sourceService, _ := flags["source-service"].GetString()
	correlationID, _ := flags["correlation-id"].GetString()
	eventType, _ := flags["event-type"].GetString()
	actorID, _ := flags["actor-id"].GetString()
	actionStatus, _ := flags["action-status"].GetString()
	payloadJSON, _ := flags["payload-json"].GetString()

	token, _ := GetStoredToken()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Info().Msgf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.RecordAuditLog(withAuth(ctx, token), &v1.AuditLogRequest{
		SourceService: sourceService,
		CorrelationId: correlationID,
		EventType:     eventType,
		ActorId:       actorID,
		ActionStatus:  actionStatus,
		PayloadJson:   payloadJSON,
	})
	if err != nil {
		log.Info().Msgf("Error: %v\n", err)
		return
	}
	log.Info().Msgf("AuditID: %d\n", resp.AuditId)
}

func ConnectUpdateSecretCapabilities(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	secretID, _ := flags["secret-id"].GetString()
	userID, _ := flags["user-id"].GetString()
	capabilitiesStr, _ := flags["capabilities"].GetString()

	token, _ := GetStoredToken()

	capabilities := splitComma(capabilitiesStr)

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Info().Msgf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.UpdateSecretCapabilities(withAuth(ctx, token), &v1.UpdateSecretCapabilitiesRequest{
		SecretId:     secretID,
		UserId:       userID,
		Capabilities: capabilities,
	})
	if err != nil {
		log.Info().Msgf("Error: %v\n", err)
		return
	}
	log.Info().Msgf("Success: %v, SecretID: %s\n", resp.Success, resp.SecretId)
}

func withAuth(ctx context.Context, token *oauth2.Token) context.Context {
	if token == nil {
		return ctx
	}
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token.AccessToken))
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
