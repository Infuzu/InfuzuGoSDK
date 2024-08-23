package infuzu

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	base "github.com/infuzu/InfuzuGoSDK/infuzu/authentication/base"
	constants "github.com/infuzu/InfuzuGoSDK/infuzu/constants"
	utils "github.com/infuzu/InfuzuGoSDK/infuzu/utils"
	"os"
)

const SignatureHeaderName = "Infuzu-Signature"

func GenerateKeyPair() (*base.IKeys, error) {
	return base.GenerateIKeys()
}

func GetPrivateKeyStr(privateKeyStr *string) (string, error) {
	if privateKeyStr != nil {
		return *privateKeyStr, nil
	}

	setPrivateKey := constants.GetSetPrivateKey()
	if setPrivateKey != "" {
		return setPrivateKey, nil
	}

	envPrivateKey := os.Getenv("INFUZU_SECRET_KEY")
	if envPrivateKey != "" {
		return envPrivateKey, nil
	}

	return "", errors.New("infuzu/authentication/shortcuts.go private key not found")
}

func GetPrivateKey(privateKeyStr *string) (*base.IPrivateKey, error) {
	privateKeyString, err := GetPrivateKeyStr(privateKeyStr)
	if err != nil {
		return nil, err
	}

	privateKey := &base.IPrivateKey{}
	err = privateKey.FromBase64(privateKeyString)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func GetPublicKey(publicKeyStr string) (*base.IPublicKey, error) {
	publicKey := &base.IPublicKey{}
	err := publicKey.FromBase64(publicKeyStr)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func GenerateMessageSignature(message string, privateKeyStr *string) (string, error) {
	privateKey, err := GetPrivateKey(privateKeyStr)
	if err != nil {
		return "", err
	}

	return privateKey.SignMessage(message, "1.2")
}

func VerifyMessageSignature(message, signature, publicKeyStr string) (bool, error) {
	publicKey, err := GetPublicKey(publicKeyStr)
	if err != nil {
		return false, err
	}

	return publicKey.VerifySignature(message, signature, 300)
}

func GetKeyPairIDFromSignature(signature string) (string, error) {
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return "", err
	}

	var signatureData map[string]interface{}
	err = json.Unmarshal(decodedSignature, &signatureData)
	if err != nil {
		return "", err
	}
	version := utils.GetSignatureVersion(signature)
	if version == "1.0" {
		if sigID, exists := signatureData["id"].(string); exists {
			return sigID, nil
		}
	} else if version == "1.2" {
		if sigID, exists := signatureData["i"].(string); exists {
			return sigID, nil
		}
	} else {
		return "", errors.New("infuzu/authentication/shortcuts.go signature version not supported")
	}

	return "", errors.New("infuzu/authentication/shortcuts.go signature id not found")
}
