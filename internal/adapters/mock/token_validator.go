package mock

import (
	"context"

	"github.com/pdaccess/pvault/internal/core/ports"
)

type mockTokenValidator struct{}

func NewAllValidValidator() ports.TokenValidator {
	return &mockTokenValidator{}
}

func (*mockTokenValidator) Validate(ctx context.Context, token string) error {
	return nil
}

type mockCryptoService struct{}

func NewCryptoService() ports.CryptoService {
	return &mockCryptoService{}
}

func (*mockCryptoService) UnwrapKey(wrappedKey, wrappingKey, nonce []byte) ([]byte, error) {
	return make([]byte, 32), nil
}

func (*mockCryptoService) Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	return ciphertext, nil
}

func (*mockCryptoService) ExtractUserRootKey(ctx context.Context) ([]byte, error) {
	return make([]byte, 32), nil
}

func (*mockCryptoService) GetServiceMasterKey() []byte {
	return make([]byte, 32)
}

func (*mockCryptoService) Encrypt(plaintext, key []byte) ([]byte, []byte, error) {
	nonce := make([]byte, 12)
	return plaintext, nonce, nil
}
