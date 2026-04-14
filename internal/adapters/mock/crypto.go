package mock

import (
	"context"
	"crypto/ecdh"

	"github.com/pdaccess/pvault/internal/core/ports"
)

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

func (*mockCryptoService) WrapForTransit(secret []byte, recipientPubKeyBytes []byte) (string, error) {
	return string(secret), nil
}

func (*mockCryptoService) UnwrapForTransit(wrappedHex string, privKey *ecdh.PrivateKey) ([]byte, error) {
	return make([]byte, 32), nil
}
