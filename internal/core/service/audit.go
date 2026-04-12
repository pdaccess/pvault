package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/rs/zerolog/log"
)

// --- Audit & System ---

func (s *Impl) GetAuditEntries(ctx context.Context, start, limit int, userID, vaultID *uuid.UUID) ([]domain.AuditEntry, error) {
	log.Info().Int("start", start).Int("limit", limit).Msg("searching audit logs")
	return s.repo.GetAuditEntries(ctx, start, limit, userID, vaultID)
}

func (s *Impl) RecordAudit(ctx context.Context, entry *domain.AuditEntry) error {
	// 1. Fetch the last entry to get the previous HMAC
	last, _ := s.repo.GetLastAuditEntry(ctx)

	// 2. Prepare Data for HMAC
	ks := s.crypto.GetServiceMasterKey()
	h := hmac.New(sha256.New, ks)

	data := fmt.Sprintf("%s%s%s%s", entry.CorrelationID, entry.EventType, entry.ActionStatus, entry.SourceService)
	h.Write([]byte(data))

	if last != nil {
		h.Write(last.CurrHMAC)
		entry.PrevHMAC = last.CurrHMAC
	}

	entry.CurrHMAC = h.Sum(nil)
	entry.UpdatedAt = time.Now()

	return s.repo.AppendAuditLog(ctx, entry)
}
