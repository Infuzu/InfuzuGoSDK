package infuzu

import (
	auth "InfuzuGOSDK/infuzu/authentication"
	"bytes"
	"encoding/json"
	"net/http"
)

type signatureSession struct {
	client *http.Client
}

func newSignatureSession() *signatureSession {
	return &signatureSession{
		client: &http.Client{},
	}
}

func (s *signatureSession) Request(
	method string, url string, body interface{}, headers map[string]string, privateKey *string,
) (*http.Response, error) {
	var err error
	var privateKeyStr string
	privateKeyStr, err = auth.GetPrivateKeyStr(privateKey)
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
	req.Header.Set(auth.SignatureHeaderName, signature)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return s.client.Do(req)

}

var signedRequests = newSignatureSession()

var SignedRequest = signedRequests.Request
