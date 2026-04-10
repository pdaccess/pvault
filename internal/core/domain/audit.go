package domain

import (
	"time"

	"github.com/google/uuid"
)

type EventType string

const (
	EventTypeCreateVault              EventType = "create_vault"
	EventTypeAddMember                EventType = "add_member"
	EventTypeProtectSecret            EventType = "protect_secret"
	EventTypeUncoverSecret            EventType = "uncover_secret"
	EventTypeDeleteSecret             EventType = "delete_secret"
	EventTypeUpdateSecretCapabilities EventType = "update_secret_capabilities"
	EventTypeCheckIn                  EventType = "check_in"
	EventTypeCheckOut                 EventType = "check_out"
)

type AuditPayload map[string]any

func (p AuditPayload) SetSecretID(id uuid.UUID)      { p["secret_id"] = id.String() }
func (p AuditPayload) SetVaultID(id uuid.UUID)       { p["vault_id"] = id.String() }
func (p AuditPayload) SetUserID(id uuid.UUID)        { p["user_id"] = id.String() }
func (p AuditPayload) SetTargetUser(id uuid.UUID)    { p["target_user"] = id.String() }
func (p AuditPayload) SetRole(role string)           { p["role"] = role }
func (p AuditPayload) SetCapabilities(caps []string) { p["capabilities"] = caps }
func (p AuditPayload) SetAction(action string)       { p["action"] = action }

type AuditEntry struct {
	ID            int64
	SourceService string
	CorrelationID uuid.UUID
	EventType     EventType
	ActorID       uuid.UUID
	ActionStatus  string
	Payload       AuditPayload
	PrevHMAC      []byte
	CurrHMAC      []byte
	UpdatedAt     time.Time
}
