package jwks

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

func TestValidateToken(t *testing.T) {
	client := resty.New()

	validator := &jwksTokenValidator{
		client: client,
		ctx:    log.With().Str("component", "jwks").Logger().WithContext(context.Background()),
		mutext: sync.RWMutex{},
	}

	if err := validator.refresh(fmt.Sprintf("http://localhost%s%s", mockJwksServerlistenAddr, mockJwksServerPath)); err != nil {
		t.Fatalf("refresh shouldn't return an error: %v", err)
	}

	var mapCliams jwt.MapClaims

	token := jwt.NewWithClaims(jwt.SigningMethodES256, mapCliams)
	tokenStr, err := token.SignedString(testPrivateKey)

	if err != nil {
		t.Fatalf("singedstring shouldn't return an error: %v", err)
	}

	err = validator.Validate(context.TODO(), tokenStr)

	if err != nil {
		t.Fatalf("validate shouldn't return an error: %v", err)
	}

}
