package service

import (
	"github.com/pdaccess/pvault/internal/core/ports"
	"github.com/rs/zerolog"
)

type Impl struct {
	repo   ports.SecretRepository
	crypto ports.CryptoService
	logger zerolog.Logger
	hasher ports.Hasher
}

func New(persistence ports.SecretRepository, c ports.CryptoService,
	h ports.Hasher, logger zerolog.Logger) (ports.VaultService, error) {

	return &Impl{
		repo:   persistence,
		crypto: c,
		logger: logger,
		hasher: h,
	}, nil
}
