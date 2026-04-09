package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"

	"github.com/pdaccess/pvault/internal/core/domain"
	"github.com/pdaccess/pvault/internal/core/ports"
)

type publicKeyJson struct {
	CurveParams *elliptic.CurveParams `json:"Curve"`
	MyX         *big.Int              `json:"X"`
	MyY         *big.Int              `json:"Y"`
}

type jwksTokenValidator struct {
	currentKey  ecdsa.PublicKey
	client      *resty.Client
	ctx         context.Context
	mux         sync.RWMutex
	mu          sync.Mutex
	refreshErr  error
	lastRefresh time.Time
}

func New(publicUrl string, syncDuration time.Duration) ports.TokenValidator {
	validator := &jwksTokenValidator{
		client: resty.New(),
		ctx:    log.With().Str("component", "jwks").Logger().WithContext(context.Background()),
	}

	if err := validator.refresh(publicUrl); err != nil {
		log.Ctx(validator.ctx).Warn().Err(err).Msg("initial JWKS fetch failed, will retry in background")
	}

	go func() {
		ticker := time.NewTicker(syncDuration)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := validator.refresh(publicUrl); err != nil {
					log.Ctx(validator.ctx).Error().Err(err).Msg("JWKS refresh failed")
				}
			}
		}
	}()

	return validator
}

func (j *jwksTokenValidator) refresh(url string) error {
	var currentKey publicKeyJson

	resp, err := j.client.R().
		SetResult(&currentKey).
		Get(url)

	if err != nil || resp.IsError() {
		err := fmt.Errorf("jwks request failed: %w", err)
		j.mu.Lock()
		j.refreshErr = err
		j.mu.Unlock()
		return err
	}

	key := ecdsa.PublicKey{
		Curve: currentKey.CurveParams,
		X:     currentKey.MyX,
		Y:     currentKey.MyY,
	}

	j.mux.Lock()
	j.currentKey = key
	j.lastRefresh = time.Now()
	j.mux.Unlock()

	j.mu.Lock()
	j.refreshErr = nil
	j.mu.Unlock()

	log.Ctx(j.ctx).Debug().Msg("JWKS refreshed successfully")
	return nil
}

func (j *jwksTokenValidator) Validate(ctx context.Context, tokenString string) error {
	j.mux.RLock()
	defer j.mux.RUnlock()

	j.mu.Lock()
	refreshErr := j.refreshErr
	j.mu.Unlock()

	if refreshErr != nil {
		return fmt.Errorf("jwks not available: %w", refreshErr)
	}

	var claims jwt.MapClaims

	_, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		return &j.currentKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return fmt.Errorf("token expired: %w", domain.ErrInvalidToken)
		}
		return fmt.Errorf("parse token: %w", domain.ErrInvalidToken)
	}

	return nil
}
