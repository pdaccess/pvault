package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type OpType int

const (
	OpTypeRead OpType = iota
	OpTypeWrite
)

type RawAudit struct {
	Id            string    `json:"id"`
	OperationTime time.Time `json:"op_time"`
	OpType        OpType    `json:"op_type"`
	UserId        string    `json:"user_id"`
	Username      string    `json:"user_name"`
}

func (r *RawAudit) String() string {
	return fmt.Sprintf("id=%s operationTime=%s", r.Id, r.OperationTime)
}

func (r *RawAudit) Bytes() ([]byte, error) {
	return json.Marshal(*r)
}

func (r *RawAudit) Restore(decrtyped []byte) error {
	return json.Unmarshal(decrtyped, r)
}

func AuditSortByOpTime(a1, a2 RawAudit) int {
	return a1.OperationTime.Compare(a2.OperationTime)
}

type AuditEntry struct {
	ID            int64
	SourceService string
	CorrelationID uuid.UUID
	EventType     string
	ActorID       uuid.UUID
	ActionStatus  string
	Payload       map[string]any // Flexible metadata
	PrevHMAC      []byte
	CurrHMAC      []byte
	UpdatedAt     time.Time
}
