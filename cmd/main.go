package main

import (
	"github.com/pdaccess/pvault/cmd/apps"
	"github.com/thatisuday/commando"
)

func main() {
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
		SetAction(apps.CreateServer)

	commando.Register("connect").
		SetShortDescription("Connect to PVault gRPC server").
		SetDescription("Connect to a PVault gRPC server and execute commands").
		AddFlag("address,a", "Server address", commando.String, "localhost:50051").
		AddFlag("tls", "Enable TLS", commando.Bool, false).
		AddFlag("token", "JWT token for authentication", commando.String, "").
		AddArgument("subcommand", "Subcommand (create-vault, create-membership, list-vaults, protect-secret, uncover-secret)", "").
		SetAction(apps.ConnectCommand)

	commando.Parse(nil)
}
