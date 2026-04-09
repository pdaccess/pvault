package service

import (
	"github.com/pdaccess/pvault/internal/core/ports"
)

type Impl struct {
	repo   ports.SecretRepository
	crypto ports.CryptoService
}

func New(persistence ports.SecretRepository, c ports.CryptoService) (ports.VaultService, error) {

	return &Impl{
		repo:   persistence,
		crypto: c,
	}, nil
}
