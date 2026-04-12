package grpc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/rs/zerolog/log"
)

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

type JWKS struct {
	client *resty.Client
	url    string
	mux    sync.RWMutex
	key    *rsa.PublicKey
}

type JWKSValidator struct {
	jwks     *JWKS
	keyID    string
	alg      string
	mu       sync.Mutex
	err      error
	lastLoad time.Time
}

func NewJWKS(url string) *JWKS {
	return &JWKS{
		client: resty.New(),
		url:    url,
	}
}

func (j *JWKS) GetKey(kid string, alg string) (*rsa.PublicKey, error) {
	resp, err := j.client.R().Get(j.url)
	if err != nil {
		return nil, fmt.Errorf("jwks request failed: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("jwks response error: %s", resp.Status())
	}

	var keys jwksResponse
	if err := json.Unmarshal(resp.Body(), &keys); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	for _, key := range keys.Keys {
		if key.Kty != "RSA" {
			continue
		}
		if kid != "" && key.Kid != kid {
			continue
		}
		if alg != "" && key.Alg != alg {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		pubKey := &rsa.PublicKey{N: n, E: e}

		j.mux.Lock()
		j.key = pubKey
		j.mux.Unlock()
		return pubKey, nil
	}
	for _, key := range keys.Keys {
		if key.Kty != "RSA" {
			continue
		}
		if kid != "" && key.Kid != kid {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		pubKey := &rsa.PublicKey{N: n, E: e}

		j.mux.Lock()
		j.key = pubKey
		j.mux.Unlock()
		return pubKey, nil
	}
	return nil, errors.New("RSA key not found in JWKS")
}

const DefaultAlg = "RS256"

func NewJWKSValidator(url string, keyID string, refreshInterval time.Duration) *JWKSValidator {
	v := &JWKSValidator{
		jwks:  NewJWKS(url),
		keyID: keyID,
		alg:   DefaultAlg,
	}
	if err := v.refresh(); err != nil {
		log.Warn().Err(err).Msg("initial JWKS fetch failed, will retry in background")
	}
	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := v.refresh(); err != nil {
				log.Error().Err(err).Msg("JWKS refresh failed")
			}
		}
	}()
	return v
}

func (v *JWKSValidator) refresh() error {
	_, err := v.jwks.GetKey(v.keyID, v.alg)
	if err != nil {
		v.mu.Lock()
		v.err = err
		v.mu.Unlock()
		return err
	}
	v.mu.Lock()
	v.err = nil
	v.lastLoad = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *JWKSValidator) GetKey() (*rsa.PublicKey, error) {
	v.mu.Lock()
	err := v.err
	v.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return v.jwks.GetKey(v.keyID, v.alg)
}

func (v *JWKSValidator) Validate(ctx context.Context, tokenString string) error {
	key, err := v.GetKey()
	if err != nil {
		return fmt.Errorf("jwks not available: %w", err)
	}

	_, err = jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return fmt.Errorf("token expired: %w", domain.ErrInvalidToken)
		}
		return fmt.Errorf("parse token: %w", domain.ErrInvalidToken)
	}
	return nil
}

func (v *JWKSValidator) Claims(tokenString string) (jwt.MapClaims, error) {
	key, err := v.GetKey()
	if err != nil {
		return nil, err
	}

	mc := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenString, &mc, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	return mc, nil
}

func (v *JWKSValidator) LastRefresh() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastLoad
}
