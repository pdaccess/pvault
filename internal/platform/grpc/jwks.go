package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	commonDomain "github.com/pdaccess/commons/pkg/domain"
	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/rs/zerolog/log"
)

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

type JWKS struct {
	client *resty.Client
	url    string
	mux    sync.RWMutex
	key    any
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

func (j *JWKS) getKey(kid string, alg string) (any, error) {
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
		if kid != "" && key.Kid != kid {
			continue
		}
		if alg != "" && key.Alg != alg && key.Alg != "" {
			continue
		}

		switch key.Kty {
		case "EC":
			return j.parseECKey(key)
		case "RSA":
			return j.parseRSAKey(key)
		}
	}

	return nil, errors.New("key not found in JWKS")
}

func (j *JWKS) parseECKey(key jwksKey) (*ecdsa.PublicKey, error) {
	curve, ok := curveForCrv(key.Crv)
	if !ok {
		return nil, fmt.Errorf("unsupported curve: %s", key.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("decode x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y coordinate: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	j.mux.Lock()
	j.key = pubKey
	j.mux.Unlock()
	return pubKey, nil
}

func (j *JWKS) parseRSAKey(key jwksKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	j.mux.Lock()
	j.key = pubKey
	j.mux.Unlock()
	return pubKey, nil
}

func curveForCrv(crv string) (elliptic.Curve, bool) {
	switch crv {
	case "P-256":
		return elliptic.P256(), true
	case "P-384":
		return elliptic.P384(), true
	case "P-521":
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

func (j *JWKS) GetKey(kid string, alg string) (any, error) {
	j.mux.RLock()
	if j.key != nil {
		defer j.mux.RUnlock()
		return j.key, nil
	}
	j.mux.RUnlock()
	return j.getKey(kid, alg)
}

const DefaultAlg = "ES256"

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
	_, err := v.jwks.getKey(v.keyID, v.alg)
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

func (v *JWKSValidator) GetKey() (any, error) {
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
		switch token.Method.(type) {
		case *jwt.SigningMethodECDSA:
			if _, ok := key.(*ecdsa.PublicKey); !ok {
				return nil, fmt.Errorf("expected ECDSA key, got %T", key)
			}
		case *jwt.SigningMethodRSA:
			if _, ok := key.(*rsa.PublicKey); !ok {
				return nil, fmt.Errorf("expected RSA key, got %T", key)
			}
		default:
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

func (v *JWKSValidator) Claims(tokenString string) (*commonDomain.PdaccessClaims, error) {
	key, err := v.GetKey()
	if err != nil {
		return nil, err
	}

	claims := &commonDomain.PdaccessClaims{}
	_, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodECDSA:
			if _, ok := key.(*ecdsa.PublicKey); !ok {
				return nil, fmt.Errorf("expected ECDSA key, got %T", key)
			}
		case *jwt.SigningMethodRSA:
			if _, ok := key.(*rsa.PublicKey); !ok {
				return nil, fmt.Errorf("expected RSA key, got %T", key)
			}
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *JWKSValidator) LastRefresh() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastLoad
}
