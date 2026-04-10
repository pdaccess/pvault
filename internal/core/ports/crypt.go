package ports

import "context"

type CryptoService interface {
	// Key Wrapping Logic
	Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error)
	Decrypt(ciphertext, key, nonce []byte) (plaintext []byte, err error)

	// Helper for the Black-Box model
	UnwrapKey(wrappedKey, wrappingKey, nonce []byte) ([]byte, error)

	// Contextual Key Retrieval
	ExtractUserRootKey(ctx context.Context) ([]byte, error) // Pulls Ku from JWT metadata
	GetServiceMasterKey() []byte                            // Accesses Ks (Safe/HSM/Env)
}
