package apps

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/pdaccess/pvault/pkg/api/v1"
	"github.com/thatisuday/commando"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func ConnectCommand(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	tlsEnabled, _ := flags["tls"].GetBool()
	token, _ := flags["token"].GetString()

	var opts []grpc.DialOption
	if tlsEnabled {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)

	subCmd := args["subcommand"].Value

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch subCmd {
	case "create-vault":
		vaultID, _ := flags["vault-id"].GetString()
		userID, _ := flags["user-id"].GetString()
		userRootKey, _ := flags["user-root-key"].GetString()

		userRootKeyBytes, err := base64.StdEncoding.DecodeString(userRootKey)
		if err != nil {
			fmt.Printf("Invalid user-root-key: %v\n", err)
			return
		}

		resp, err := client.CreateVault(withAuth(ctx, token), &v1.CreateVaultRequest{
			VaultId:     vaultID,
			UserId:      userID,
			UserRootKey: userRootKeyBytes,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Success: %v, Message: %s\n", resp.Success, resp.Message)

	case "create-membership":
		userID, _ := flags["user-id"].GetString()
		vaultID, _ := flags["vault-id"].GetString()
		userRootKey, _ := flags["user-root-key"].GetString()
		role, _ := flags["role"].GetString()
		capabilitiesStr, _ := flags["capabilities"].GetString()

		userRootKeyBytes, err := base64.StdEncoding.DecodeString(userRootKey)
		if err != nil {
			fmt.Printf("Invalid user-root-key: %v\n", err)
			return
		}

		var capabilities []string
		if capabilitiesStr != "" {
			capabilities = splitComma(capabilitiesStr)
		}

		resp, err := client.CreateMembership(withAuth(ctx, token), &v1.CreateMembershipRequest{
			UserId:       userID,
			VaultId:      vaultID,
			UserRootKey:  userRootKeyBytes,
			Role:         role,
			Capabilities: capabilities,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Success: %v, Message: %s\n", resp.Success, resp.Message)

	case "list-vaults":
		resp, err := client.ListAuthorizedVaults(withAuth(ctx, token), &v1.ListVaultsRequest{})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Vault IDs: %v\n", resp.VaultIds)

	case "protect-secret":
		secretID, _ := flags["secret-id"].GetString()
		vaultID, _ := flags["vault-id"].GetString()
		plaintext, _ := flags["plaintext"].GetString()

		resp, err := client.ProtectSecret(withAuth(ctx, token), &v1.ProtectSecretRequest{
			SecretId:  secretID,
			VaultId:   vaultID,
			Plaintext: plaintext,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Success: %v, SecretID: %s\n", resp.Success, resp.SecretId)

	case "uncover-secret":
		secretID, _ := flags["secret-id"].GetString()
		vaultID, _ := flags["vault-id"].GetString()
		action, _ := flags["action"].GetString()

		resp, err := client.UncoverSecret(withAuth(ctx, token), &v1.UncoverSecretRequest{
			SecretId: secretID,
			VaultId:  vaultID,
			Action:   action,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Plaintext: %s\n", resp.Plaintext)

	case "record-audit":
		sourceService, _ := flags["source-service"].GetString()
		correlationID, _ := flags["correlation-id"].GetString()
		eventType, _ := flags["event-type"].GetString()
		actorID, _ := flags["actor-id"].GetString()
		actionStatus, _ := flags["action-status"].GetString()
		payloadJSON, _ := flags["payload-json"].GetString()

		resp, err := client.RecordAuditLog(withAuth(ctx, token), &v1.AuditLogRequest{
			SourceService: sourceService,
			CorrelationId: correlationID,
			EventType:     eventType,
			ActorId:       actorID,
			ActionStatus:  actionStatus,
			PayloadJson:   payloadJSON,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("AuditID: %d\n", resp.AuditId)

	default:
		fmt.Printf("Unknown subcommand: %s\n", subCmd)
	}
}

func ConnectCreateVault(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := flags["token"].GetString()
	vaultID, _ := flags["vault-id"].GetString()
	userID, _ := flags["user-id"].GetString()
	userRootKey, _ := flags["user-root-key"].GetString()

	userRootKeyBytes, err := base64.StdEncoding.DecodeString(userRootKey)
	if err != nil {
		fmt.Printf("Invalid user-root-key: %v\n", err)
		return
	}

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.CreateVault(withAuth(ctx, token), &v1.CreateVaultRequest{
		VaultId:     vaultID,
		UserId:      userID,
		UserRootKey: userRootKeyBytes,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Success: %v, Message: %s\n", resp.Success, resp.Message)
}

func ConnectCreateMembership(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := flags["token"].GetString()
	userID, _ := flags["user-id"].GetString()
	vaultID, _ := flags["vault-id"].GetString()
	userRootKey, _ := flags["user-root-key"].GetString()
	role, _ := flags["role"].GetString()
	capabilitiesStr, _ := flags["capabilities"].GetString()

	userRootKeyBytes, err := base64.StdEncoding.DecodeString(userRootKey)
	if err != nil {
		fmt.Printf("Invalid user-root-key: %v\n", err)
		return
	}

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	capabilities := splitComma(capabilitiesStr)

	resp, err := client.CreateMembership(withAuth(ctx, token), &v1.CreateMembershipRequest{
		UserId:       userID,
		VaultId:      vaultID,
		UserRootKey:  userRootKeyBytes,
		Role:         role,
		Capabilities: capabilities,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Success: %v, Message: %s\n", resp.Success, resp.Message)
}

func ConnectListVaults(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := flags["token"].GetString()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ListAuthorizedVaults(withAuth(ctx, token), &v1.ListVaultsRequest{})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Vault IDs: %v\n", resp.VaultIds)
}

func ConnectProtectSecret(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := flags["token"].GetString()
	secretID, _ := flags["secret-id"].GetString()
	vaultID, _ := flags["vault-id"].GetString()
	plaintext, _ := flags["plaintext"].GetString()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
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
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Success: %v, SecretID: %s\n", resp.Success, resp.SecretId)
}

func ConnectUncoverSecret(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := flags["token"].GetString()
	secretID, _ := flags["secret-id"].GetString()
	vaultID, _ := flags["vault-id"].GetString()
	action, _ := flags["action"].GetString()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	client := v1.NewPVaultServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.UncoverSecret(withAuth(ctx, token), &v1.UncoverSecretRequest{
		SecretId: secretID,
		VaultId:  vaultID,
		Action:   action,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Plaintext: %s\n", resp.Plaintext)
}

func ConnectRecordAudit(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	serverAddr, _ := flags["address"].GetString()
	token, _ := flags["token"].GetString()
	sourceService, _ := flags["source-service"].GetString()
	correlationID, _ := flags["correlation-id"].GetString()
	eventType, _ := flags["event-type"].GetString()
	actorID, _ := flags["actor-id"].GetString()
	actionStatus, _ := flags["action-status"].GetString()
	payloadJSON, _ := flags["payload-json"].GetString()

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
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
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("AuditID: %d\n", resp.AuditId)
}

func withAuth(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, "token", token)
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
