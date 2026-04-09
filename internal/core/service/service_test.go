package service

import (
	"context"
	"os"
	"testing"

	"github.com/pdaccess/pvault/internal/adapters/mock"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/rs/zerolog/log"
)

var (
	ctx  context.Context
	impl ports.VaultService
)

func TestMain(m *testing.M) {
	ctx = log.With().
		Str("component", "module").
		Logger().WithContext(context.Background())

	var err error

	impl, err = New(mock.New(), mock.NewCryptoService(), mock.NewAllValidValidator())
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("service init")
		os.Exit(1)
	}

	ctx = context.WithValue(ctx, domain.UserTokenIn, "empty")

	m.Run()
}
