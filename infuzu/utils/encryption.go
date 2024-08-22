package infuzu

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func ComputeSHA256(text string) (string, error) {
	if text == "" {
		return "", errors.New("infuzu/utils/encryption.go input text cannot be empty")
	}

	hash := sha256.New()
	hash.Write([]byte(text))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}
