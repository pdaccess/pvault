package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	currentKey ecdsa.PublicKey
	client     *resty.Client
	ctx        context.Context
	mutext     sync.RWMutex
}

func New(publicUrl string, syncDuration time.Duration) ports.TokenValidator {

	client := resty.New()

	validator := &jwksTokenValidator{
		client: client,
		ctx:    log.With().Str("component", "jwks").Logger().WithContext(context.Background()),
		mutext: sync.RWMutex{},
	}

	go func() {
		timer := time.NewTicker(syncDuration)

		defer timer.Stop()

		for ; true; <-timer.C {
			if err := validator.refresh(publicUrl); err != nil {
				log.Ctx(validator.ctx).
					Err(err).Msg("wrong response")
			}
		}
	}()

	return validator
}

// Validate implements ports.TokenValidator.
func (j *jwksTokenValidator) refresh(url string) error {
	var currentKey publicKeyJson

	resp, err := j.client.R().
		SetResult(&currentKey).
		Get(url)

	if err != nil || resp.IsError() {
		return fmt.Errorf("wrong response: %w resp: %v", err, resp.Error())
	}
	j.mutext.Lock()
	j.currentKey.Curve = currentKey.CurveParams
	j.currentKey.X = currentKey.MyX
	j.currentKey.Y = currentKey.MyY
	j.mutext.Unlock()

	return nil
}

// Validate implements ports.TokenValidator.
func (j *jwksTokenValidator) Validate(ctx context.Context, tokenString string) error {
	j.mutext.RLock()
	defer j.mutext.RUnlock()

	var cliams jwt.MapClaims

	_, err := jwt.ParseWithClaims(tokenString, &cliams, func(token *jwt.Token) (any, error) {
		return &j.currentKey, nil
	})

	if err != nil {
		return fmt.Errorf("parsewithclaims: %v : %w", err, domain.ErrInvalidToken)
	}

	return nil
}
