package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
)

type aesGcmService struct {
	masterKey []byte
}

func NewAESGCMService(key []byte) ports.CryptoService {
	return &aesGcmService{masterKey: key}
}

// UnwrapKey is essentially Decrypt but semantically used for key-wrapping logic
func (s *aesGcmService) UnwrapKey(wrappedKey, wrappingKey, nonce []byte) ([]byte, error) {
	return s.Decrypt(wrappedKey, wrappingKey, nonce)
}

// Decrypt handles the AES-GCM decryption logic
func (s *aesGcmService) Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher block creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM mode creation failed: %w", err)
	}

	// AES-GCM automatically verifies the authentication tag appended to the ciphertext
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: authentication tag mismatch or invalid key")
	}

	return plaintext, nil
}

// ExtractUserRootKey retrieves the Ku that the JWT auth interceptor placed in context.
func (s *aesGcmService) ExtractUserRootKey(ctx context.Context) ([]byte, error) {
	val := ctx.Value(domain.ContextKeyUserRootKey)
	if ku, ok := val.([]byte); ok {
		return ku, nil
	}
	return nil, errors.New("user root key (Ku) missing from context")
}

func (s *aesGcmService) Encrypt(plaintext, key []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, 12) // Standard GCM nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Seal appends the authentication tag to the result
	ciphertext = aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// GetServiceMasterKey implements [ports.CryptoService].
func (s *aesGcmService) GetServiceMasterKey() []byte {
	return s.masterKey
}

func (s *aesGcmService) WrapForTransit(secret []byte, recipientPubKeyBytes []byte) (string, error) {
	remotePubKey, err := ecdh.P256().NewPublicKey(recipientPubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("invalid recipient public key: %w", err)
	}

	ephemeralPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	sharedSecret, err := ephemeralPriv.ECDH(remotePubKey)
	if err != nil {
		return "", err
	}

	aesKey := sha256.Sum256(sharedSecret)

	block, _ := aes.NewCipher(aesKey[:])
	aesgcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, secret, nil)

	result := append(ephemeralPriv.PublicKey().Bytes(), nonce...)
	result = append(result, ciphertext...)

	return hex.EncodeToString(result), nil
}
