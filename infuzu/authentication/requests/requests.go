package infuzu

import (
	"errors"
	"fmt"
	base "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/base"
)

type Application struct {
	ID          *string `json:"id"`
	Name        *string `json:"name"`
	Description *string `json:"description,omitempty"`
	IsInternal  *bool   `json:"is_internal,omitempty"`
}

func (a Application) String() string {
	return fmt.Sprintf("%s (%s)", *a.Name, *a.ID)
}

type AuthenticationKey struct {
	Valid          *bool        `json:"valid"`
	ID             *string      `json:"id"`
	Name           *string      `json:"name"`
	PublicKeyB64   *string      `json:"public_key_b64"`
	PrivateKeyHash *string      `json:"private_key_hash,omitempty"`
	Application    *Application `json:"application,omitempty"`
}

func (ak AuthenticationKey) String() string {
	if ak.Valid != nil && *ak.Valid {
		return fmt.Sprintf("%s (%s)", *ak.Name, (*ak.Application).String())
	}
	return fmt.Sprintf("%s (INVALID)", *ak.Name)
}

func (ak AuthenticationKey) PublicKey() (*base.IPublicKey, error) {
	if ak.PublicKeyB64 == nil {
		return nil, errors.New("infuzu/authentication/requests.go authentication key has no public key")
	}
	var pk base.IPublicKey
	err := pk.FromBase64(*ak.PublicKeyB64)
	return &pk, err
}
