package domain

import (
	"time"

	"github.com/google/uuid"
)

type IdentityProvider string

const (
	ProviderLocal    IdentityProvider = "local"
	ProviderKeycloak IdentityProvider = "keycloak"
	ProviderLDAP     IdentityProvider = "ldap"
)

type Identity struct {
	InternalID    uuid.UUID
	Provider      IdentityProvider
	LocalUsername *string
	PasswordHash  *string
	ExternalID    *string
	WrappedKU     []byte
	KUNonce       []byte
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
