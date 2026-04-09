package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/pdaccess/pvault/internal/core/domain"
)

// --- Audit & System ---

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
