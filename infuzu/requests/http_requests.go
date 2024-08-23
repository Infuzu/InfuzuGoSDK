package infuzu

import (
	auth "InfuzuGOSDK/infuzu/authentication/shortcuts"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type SignatureSession struct {
	*http.Client
	privateKey *string
}

func newSignatureSession(privateKey *string) *SignatureSession {
	return &SignatureSession{
		Client: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
		privateKey: privateKey,
	}
}

func (s *SignatureSession) Request(
	method string, url string, body interface{}, headers map[string]string,
) (*http.Response, error) {
	var err error
	var privateKeyStr string
	privateKeyStr, err = auth.GetPrivateKeyStr(s.privateKey)
	if err != nil {
		return nil, err
	}

	var requestBody []byte

	if body != nil {
		if str, ok := body.(string); ok {
			requestBody = []byte(str)
		} else {
			requestBody, err = json.Marshal(body)
			if err != nil {
				return nil, err
			}
		}
	}

	var req *http.Request
	req, err = http.NewRequest(method, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	var signature string
	signature, err = auth.GenerateMessageSignature(string(requestBody), &privateKeyStr)
	if err != nil {
		return nil, err
	}

	_, exists := headers[auth.SignatureHeaderName]

	if exists {
		return nil, fmt.Errorf("cannot include signature header")
	}

	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	req.Header.Set(auth.SignatureHeaderName, signature)

	return s.Do(req)

}

var SignedClient = newSignatureSession(nil)
