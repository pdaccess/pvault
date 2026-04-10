package ports

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenValidator interface {
	Validate(ctx context.Context, token string) error
}

type JWKSValidator interface {
	GetKey() (*rsa.PublicKey, error)
	Validate(ctx context.Context, token string) error
	Claims(token string) (jwt.MapClaims, error)
	LastRefresh() time.Time
}
