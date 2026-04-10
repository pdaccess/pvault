package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pdaccess/pvault/cmd/apps"
	"github.com/rs/zerolog/log"
	"github.com/thatisuday/commando"
)

const tokenFileName = ".pvault/token"

var Commit, BuildTime, BuildEnv string

func main() {
	log.Info().
		Str("Commnit", Commit).
		Str("BuildTime", BuildTime).
		Str("nBuildEnv", BuildEnv).
		Send()

	commando.SetExecutableName("pvault").
		SetVersion("v1.0.0").
		SetDescription("PVault CLI")

	commando.Register(nil).
		AddFlag("listen,l", "listen address", commando.String, ":50051").
		AddFlag("db,d", "PostgreSQL connection string", commando.String, "").
		AddFlag("tls,t", "Enable TLS", commando.Bool, false).
		AddFlag("tls-cert", "TLS certificate file", commando.String, "cert/server.crt").
		AddFlag("tls-key", "TLS key file", commando.String, "cert/server.key").
		AddFlag("log-level,v", "Log level (debug, info, warn, error)", commando.String, "info").
		AddFlag("jwks", "JWKS URL for RS256 token validation", commando.String, "http://keycloak:8080/realms/pvault/protocol/openid-connect/certs").
		SetAction(apps.CreateServer)

	commando.Register("login").
		SetShortDescription("Login to Keycloak and save token").
		AddFlag("keycloak", "Keycloak URL", commando.String, "http://localhost:8180").
		AddFlag("client-id", "OAuth client ID", commando.String, "pvault-client").
		AddFlag("client-secret", "OAuth client secret", commando.String, "pvault-client-secret").
		SetAction(apps.ConnectLogin)

	commando.Register("logout").
		SetShortDescription("Remove stored token").
		SetAction(func(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Println("Failed to get home directory:", err)
				return
			}
			tokenPath := filepath.Join(homeDir, tokenFileName)
			if err := os.Remove(tokenPath); err != nil {
				if os.IsNotExist(err) {
					fmt.Println("No token found")
					return
				}
				fmt.Println("Failed to remove token:", err)
				return
			}
			fmt.Println("Token removed")
		})

	commando.Register("create-vault").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("vault-id", "Vault ID (UUID)", commando.String, "").
		SetAction(apps.ConnectCreateVault)

	commando.Register("create-membership").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("user-id", "User ID (UUID)", commando.String, "").
		AddFlag("vault-id", "Vault ID (UUID)", commando.String, "").
		AddFlag("user-root-key", "User root key (base64 encoded)", commando.String, "").
		AddFlag("role", "Role", commando.String, "").
		AddFlag("capabilities", "Capabilities (comma-separated)", commando.String, "").
		SetAction(apps.ConnectCreateMembership)

	commando.Register("list-vaults").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		SetAction(apps.ConnectListVaults)

	commando.Register("protect-secret").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("secret-id", "Secret ID (UUID)", commando.String, "").
		AddFlag("vault-id", "Vault ID (UUID)", commando.String, "").
		AddFlag("plaintext", "Plaintext secret", commando.String, "").
		SetAction(apps.ConnectProtectSecret)

	commando.Register("uncover-secret").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("secret-id", "Secret ID (UUID)", commando.String, "").
		AddFlag("action", "Action (e.g., connect, see)", commando.String, "").
		SetAction(apps.ConnectUncoverSecret)

	commando.Register("record-audit").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("source-service", "Source service", commando.String, "").
		AddFlag("correlation-id", "Correlation ID (UUID)", commando.String, "").
		AddFlag("event-type", "Event type", commando.String, "").
		AddFlag("actor-id", "Actor ID (UUID)", commando.String, "").
		AddFlag("action-status", "Action status", commando.String, "").
		AddFlag("payload-json", "Payload JSON", commando.String, "").
		SetAction(apps.ConnectRecordAudit)

	commando.Register("protect-secret").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("secret-id", "Secret ID (UUID)", commando.String, "").
		AddFlag("vault-id", "Vault ID (UUID)", commando.String, "").
		AddFlag("plaintext", "Plaintext secret", commando.String, "").
		AddFlag("capabilities", "Capabilities (comma-separated)", commando.String, "see,connect").
		SetAction(apps.ConnectProtectSecret)

	commando.Register("update-secret-capabilities").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("secret-id", "Secret ID (UUID)", commando.String, "").
		AddFlag("user-id", "Target User ID (UUID)", commando.String, "").
		AddFlag("capabilities", "Capabilities (comma-separated)", commando.String, "").
		SetAction(apps.ConnectUpdateSecretCapabilities)

	commando.Parse(nil)
}
