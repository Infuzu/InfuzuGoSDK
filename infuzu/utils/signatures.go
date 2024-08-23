package infuzu

import (
	"encoding/base64"
	"encoding/json"
)

func GetSignatureVersion(signature string) string {
	var decodedSignature []byte
	var err error
	decodedSignature, err = base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return "1.0"
	}

	var signatureMap map[string]interface{}
	err = json.Unmarshal(decodedSignature, &signatureMap)
	if err != nil {
		return "1.0"
	}

	version, ok := signatureMap["v"]
	if !ok {
		return "1.0"
	}
	return version.(string)
}
