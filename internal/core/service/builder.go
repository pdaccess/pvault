package service

import (
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/rs/zerolog"
)

type Impl struct {
	repo   ports.SecretRepository
	crypto ports.CryptoService
	logger zerolog.Logger
}

func New(persistence ports.SecretRepository, c ports.CryptoService, logger zerolog.Logger) (ports.VaultService, error) {

	return &Impl{
		repo:   persistence,
		crypto: c,
		logger: logger,
	}, nil
}
