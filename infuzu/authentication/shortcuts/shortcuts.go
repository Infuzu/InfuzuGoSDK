package infuzu

import (
	base "InfuzuGOSDK/infuzu/authentication/base"
	constants "InfuzuGOSDK/infuzu/constants"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	return privateKey.SignMessage(message)
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

	if sigID, exists := signatureData["id"].(string); exists {
		return sigID, nil
	}

	return "", errors.New("infuzu/authentication/shortcuts.go signature id not found")
}
