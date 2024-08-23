package infuzu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gibson042/canonicaljson-go"
	utils "github.com/infuzu/infuzu-go-sdk/infuzu/utils"
	"math/big"
	"time"
)

var curve = elliptic.P521()

type IKey interface {
	ToBase64() (string, error)
	FromBase64(encoded string) error
}

type IPublicKey struct {
	PublicKey *ecdsa.PublicKey
	KeyPairID string
}

func (pk *IPublicKey) ToBase64() (string, error) {
	publicKeyBytes := elliptic.MarshalCompressed(pk.PublicKey.Curve, pk.PublicKey.X, pk.PublicKey.Y)
	publicKeyStr := base64.URLEncoding.EncodeToString(publicKeyBytes)
	publicKeyMap := map[string]string{
		"u": publicKeyStr,
		"i": pk.KeyPairID,
	}
	publicKeyJson, err := json.Marshal(publicKeyMap)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(publicKeyJson), nil
}

func (pk *IPublicKey) FromBase64(encoded string) error {
	var decodedBytes []byte
	var err error
	decodedBytes, err = base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	var publicKeyMap map[string]string
	err = json.Unmarshal(decodedBytes, &publicKeyMap)
	if err != nil {
		return err
	}
	publicKeyStr := publicKeyMap["u"]
	pk.KeyPairID = publicKeyMap["i"]
	var publicKeyBytes []byte
	publicKeyBytes, err = base64.URLEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return err
	}
	x, y := elliptic.UnmarshalCompressed(curve, publicKeyBytes)
	if x == nil {
		return errors.New("invalid public key")
	}
	pk.PublicKey = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return nil
}

type IPrivateKey struct {
	PrivateKey *ecdsa.PrivateKey
	KeyPairID  string
}

func (sk *IPrivateKey) ToBase64() (string, error) {
	var err error
	var privateKeyBytes []byte
	privateKeyBytes, err = x509.MarshalECPrivateKey(sk.PrivateKey)
	if err != nil {
		return "", err
	}
	privateKeyStr := base64.URLEncoding.EncodeToString(privateKeyBytes)
	privateKeyMap := map[string]string{
		"u": privateKeyStr,
		"i": sk.KeyPairID,
	}
	var privateKeyJson []byte
	privateKeyJson, err = json.Marshal(privateKeyMap)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(privateKeyJson), nil
}

func (sk *IPrivateKey) FromBase64(encoded string) error {
	var err error
	var decodedBytes []byte
	decodedBytes, err = base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	var privateKeyMap map[string]string
	err = json.Unmarshal(decodedBytes, &privateKeyMap)
	if err != nil {
		return err
	}
	privateKeyStr, ok := privateKeyMap["r"]
	if !ok {
		return fmt.Errorf("missing key 'r' in private key map")
	}

	sk.KeyPairID = privateKeyMap["i"]
	var privateKeyBytes []byte
	privateKeyBytes, err = base64.URLEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return err
	}

	privateKeyInt := new(big.Int).SetBytes(privateKeyBytes)

	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = curve
	privateKey.D = privateKeyInt
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKey.D.Bytes())

	sk.PrivateKey = privateKey

	return nil
}

func GenerateIPrivateKey() (*IPrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	keyPairID := utils.CreateUUIDWithoutDash()
	return &IPrivateKey{
		PrivateKey: privateKey,
		KeyPairID:  keyPairID,
	}, nil
}

func (sk *IPrivateKey) SignMessage(message string, version string) (string, error) {
	if version == "1.0" {
		timestamp := time.Now().Unix()
		messageWithMetadata := map[string]interface{}{
			"id":        sk.KeyPairID,
			"message":   message,
			"timestamp": timestamp,
		}
		var messageJson []byte
		var err error
		messageJson, err = canonicaljson.Marshal(messageWithMetadata)
		if err != nil {
			return "", err
		}
		hashed := sha256.Sum256(messageJson)

		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, sk.PrivateKey, hashed[:])
		if err != nil {
			return "", err
		}

		var derSig []byte
		derSig, err = asn1.Marshal(EcdsaSignature{
			R: r,
			S: s,
		})
		if err != nil {
			return "", err
		}

		baseSignatureStr := base64.URLEncoding.EncodeToString(derSig)
		fullSignatureMap := map[string]interface{}{
			"signature": baseSignatureStr,
			"timestamp": timestamp,
			"id":        sk.KeyPairID,
		}
		var fullSignatureJson []byte
		fullSignatureJson, err = json.Marshal(fullSignatureMap)
		if err != nil {
			return "", err
		}

		return base64.URLEncoding.EncodeToString(fullSignatureJson), nil
	} else if version == "1.2" {
		timestamp := time.Now().Unix()
		messageWithMetadata := map[string]interface{}{
			"i": sk.KeyPairID,
			"m": message,
			"t": timestamp,
		}
		var messageJson []byte
		var err error
		messageJson, err = canonicaljson.Marshal(messageWithMetadata)
		if err != nil {
			return "", err
		}
		hashed := sha256.Sum256(messageJson)

		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, sk.PrivateKey, hashed[:])
		if err != nil {
			return "", err
		}

		var derSig []byte
		derSig, err = asn1.Marshal(EcdsaSignature{
			R: r,
			S: s,
		})
		if err != nil {
			return "", err
		}

		baseSignatureStr := base64.URLEncoding.EncodeToString(derSig)
		fullSignatureMap := map[string]interface{}{
			"s": baseSignatureStr,
			"t": timestamp,
			"i": sk.KeyPairID,
			"v": "1.2",
		}
		var fullSignatureJson []byte
		fullSignatureJson, err = json.Marshal(fullSignatureMap)
		if err != nil {
			return "", err
		}

		return base64.URLEncoding.EncodeToString(fullSignatureJson), nil
	} else {
		return "", fmt.Errorf("unsupported version: %s", version)
	}
}

type EcdsaSignature struct {
	R, S *big.Int
}

func (sk *IPrivateKey) PublicKey() *IPublicKey {
	return &IPublicKey{
		PublicKey: &sk.PrivateKey.PublicKey,
		KeyPairID: sk.KeyPairID,
	}
}

func (pk *IPublicKey) VerifySignature(message string, signature string, allowedTimeDifference int) (bool, error) {
	var decodedSignature []byte
	var err error
	decodedSignature, err = base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	var signatureMap map[string]interface{}
	err = json.Unmarshal(decodedSignature, &signatureMap)
	if err != nil {
		return false, err
	}
	sigTimestamp := int64(signatureMap["timestamp"].(float64))
	var sigSignature []byte
	sigSignature, err = base64.URLEncoding.DecodeString(signatureMap["signature"].(string))
	if err != nil {
		return false, err
	}
	sigID := signatureMap["id"].(string)

	if sigID != pk.KeyPairID {
		return false, nil
	}

	if time.Now().Unix()-sigTimestamp > int64(allowedTimeDifference) {
		return false, nil
	}

	messageWithMetadata := map[string]interface{}{
		"message":   message,
		"timestamp": sigTimestamp,
		"id":        sigID,
	}
	var messageJson []byte
	messageJson, err = json.Marshal(messageWithMetadata)
	if err != nil {
		return false, err
	}
	hashed := sha256.Sum256(messageJson)

	var esig EcdsaSignature
	_, err = asn1.Unmarshal(sigSignature, &esig)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(pk.PublicKey, hashed[:], esig.R, esig.S)
	return valid, nil
}

type IKeys struct {
	PrivateKey *IPrivateKey
	PublicKey  *IPublicKey
	ID         string
}

func GenerateIKeys() (*IKeys, error) {
	privateKey, err := GenerateIPrivateKey()
	if err != nil {
		return nil, err
	}
	return &IKeys{
		PrivateKey: privateKey,
		PublicKey:  privateKey.PublicKey(),
		ID:         privateKey.KeyPairID,
	}, nil
}

func (ik *IKeys) String() string {
	privateKeyBase64, _ := ik.PrivateKey.ToBase64()
	publicKeyBase64, _ := ik.PublicKey.ToBase64()
	return "Key Pair ID: " + ik.ID + "\nPrivate Key: " + privateKeyBase64 + "\nPublic Key: " + publicKeyBase64
}
