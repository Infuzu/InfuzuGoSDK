package infuzu

import (
	"errors"
	"fmt"
	application "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/applications"
	base "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/base"
	requests "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/requests"
	shortcuts "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/shortcuts"
	"reflect"
)

func VerifyDiverseMessageSignature(message string, signature string, publicKey interface{}) (bool, error) {
	var publicKeyB64 string
	var err error

	switch pk := publicKey.(type) {
	case *requests.AuthenticationKey:
		if pk.PublicKeyB64 == nil {
			return false, errors.New("invalid public key base64")
		}
		publicKeyB64 = *pk.PublicKeyB64
	case *base.IPublicKey:
		publicKeyB64, err = pk.ToBase64()
		if err != nil {
			return false, err
		}
	case *string:
		publicKeyB64 = *pk
	case string:
		publicKeyB64 = pk
	default:
		return false, errors.New(fmt.Sprintf("public key must be of the type AuthenticationKey, IPublicKey IKeys, or string. Instead got %s", reflect.TypeOf(publicKey)))
	}

	if publicKeyB64 == "" {
		return false, errors.New("public key base64 is empty")
	}

	return shortcuts.VerifyMessageSignature(message, signature, publicKeyB64)
}

func ConvertMessageSignatureToApplicationAndVerify(signature string, message string) (*requests.Application, error) {
	var pairID string
	var err error
	pairID, err = shortcuts.GetKeyPairIDFromSignature(signature)
	if err != nil {
		return nil, err
	}
	if pairID == "" {
		return nil, errors.New("invalid signature")
	}

	var authenticationKey *requests.AuthenticationKey
	authenticationKey, err = application.GetApplicationInformation(pairID)
	if err != nil {
		return nil, err
	}

	if authenticationKey.PublicKeyB64 == nil {
		return nil, errors.New("invalid public key base64")
	}

	var sigIsValid bool
	sigIsValid, err = VerifyDiverseMessageSignature(message, signature, authenticationKey.PublicKeyB64)
	if err != nil {
		return nil, err
	}
	if !sigIsValid {
		return nil, errors.New("invalid signature")
	}

	return authenticationKey.Application, nil
}

func ApplicationIsValid(application interface{}) bool {
	_, ok := application.(*requests.Application)
	return ok
}

func ApplicationIsInternal(application interface{}) bool {
	app, ok := application.(*requests.Application)
	if !ok {
		return false
	}
	return app.IsInternal != nil && *app.IsInternal
}

func ApplicationIsInList(application interface{}, appIDs []string) bool {
	app, ok := application.(*requests.Application)
	if !ok {
		return false
	}

	for _, id := range appIDs {
		if id == *app.ID {
			return true
		}
	}
	return false
}
