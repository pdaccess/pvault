package domain

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidCapability = errors.New("invalid capability")

	CapSee     = Capability("see")
	CapConnect = Capability("connect")
	CapWrite   = Capability("write")
	CapCheck   = Capability("check")
	CapMngt    = Capability("mngt")

	ValidCapabilities = Capabilities{CapSee, CapConnect, CapWrite, CapCheck, CapMngt}
)

type Capability string

func (c Capability) String() string { return string(c) }

func (c Capability) IsValid() bool {
	return slices.Contains(ValidCapabilities, c)
}

type Capabilities []Capability

func (c Capabilities) CanExecute(action string) bool {
	actionCap := Capability(action)
	if slices.Contains(c, actionCap) {
		return true
	}

	return false
}

func (c Capabilities) HasAll(other Capabilities) bool {
	for _, cap := range other {
		if !slices.Contains(c, cap) {
			return false
		}
	}
	return true
}

func (c Capabilities) Validate() error {
	for _, cap := range c {
		if !slices.Contains(ValidCapabilities, cap) {
			return fmt.Errorf("%w: %s", ErrInvalidCapability, cap)
		}
	}
	return nil
}

func (c Capabilities) Strings() []string {
	result := make([]string, len(c))
	for i, cap := range c {
		result[i] = cap.String()
	}
	return result
}

func CapabilitiesFromStrings(s []string) Capabilities {
	var result Capabilities
	for _, c := range s {
		cap := Capability(c)
		result = append(result, cap)
	}
	return result
}

type SecretValue struct {
	ID            uuid.UUID
	VaultID       uuid.UUID
	CreatorUserID uuid.UUID
	Ciphertext    []byte // The actual data encrypted by DEK
	WrappedDEK    []byte // The DEK wrapped by Vault Key (Kv)
	Nonce         []byte // IV for the ciphertext
	Version       int
	UpdatedAt     time.Time
}

type UserSecretCapabilities struct {
	UserID       uuid.UUID
	SecretID     uuid.UUID
	Capabilities Capabilities // e.g., [see, connect, write]
	UpdatedAt    time.Time
}

func (u *UserSecretCapabilities) CanExecute(action string) bool {
	return u.Capabilities.CanExecute(action)
}

type MasterWrap struct {
	VaultID          uuid.UUID
	MasterWrappedKey []byte // The Kv wrapped by Service Master Key (Ks)
	Nonce            []byte
	UpdatedAt        time.Time
}

type SecretCheckout struct {
	SecretID     uuid.UUID
	Version      int
	UserID       uuid.UUID
	CheckedOutAt time.Time
}

const CheckoutTimeout = 1 * time.Hour

func (s *SecretCheckout) IsExpired() bool {
	return time.Since(s.CheckedOutAt) > CheckoutTimeout
}
