package service

import (
	"github.com/pdaccess/pvault/internal/core/ports"
)

type Impl struct {
	repo       ports.SecretRepository
	validators []ports.TokenValidator
	crypto     ports.CryptoService
}

func New(persistence ports.SecretRepository, c ports.CryptoService, tokenValidators ...ports.TokenValidator) (ports.VaultService, error) {

	return &Impl{
		repo:       persistence,
		validators: tokenValidators,
		crypto:     c,
	}, nil
}
